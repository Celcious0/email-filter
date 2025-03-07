import sys
import smtplib
import hashlib
from email.policy import default
from email import message_from_bytes
import asyncio
import logging
import os
from email.parser import BytesParser
from email.header import decode_header
from aiosmtpd.controller import Controller

# 로그 설정
logging.basicConfig(filename="/var/log/filtering_server.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

# 필터링할 키워드 목록
BLOCKED_KEYWORDS = ["malware", "phishing", "badlink"]

# 위험 확장자 목록
BLOCKED_EXTENSIONS = ['.exe', '.bat', '.js', '.vbs', '.msi', '.py']

# MIME 매핑 테이블: 확장자별 올바른 MIME 타입 매핑
MIME_MAPPING = {
    '.txt': 'text/plain',
    '.pdf': 'application/pdf',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png'
}

# 악성코드 MD5 해시값 리스트 (악성코드 샘플 해시값)
MALICIOUS_HASHES = {
    "c095272b8480b9033a7a1d5b2fa1cf84",  # 악성코드 1
    "29b3d6974d2c36be6715022bc04dee09"   # 악성코드 2
}



# MD5 해시 계산 모듈
def compute_md5(data: bytes) -> str:
    """입력된 데이터를 대상으로 MD5 해시값(16진수 문자열)을 계산하여 반환."""
    md5_hash = hashlib.md5()
    md5_hash.update(data)
    return md5_hash.hexdigest()

# SHA-256 해시 계산 모듈
def compute_sha256(data: bytes) -> str:
    """입력된 데이터를 대상으로 SHA-256 해시값(16진수 문자열)을 계산하여 반환."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()

# 다중 해시 알고리즘 동시 적용 기능
def compute_multi_hash(data: bytes) -> dict:
    """
    입력된 데이터에 대해 MD5와 SHA-256 해시를 동시에 계산하여,
    결과를 딕셔너리 형태로 반환합니다.
    """
    return {
        "MD5": compute_md5(data),
        "SHA256": compute_sha256(data)
    }

##############################################
# FilterHandler 클래스 (aiosmtpd 기반)
class FilterHandler:
    async def handle_DATA(self, server, session, envelope):
        # 이메일 파싱
        mail_data = BytesParser().parsebytes(envelope.content)
        # Subject 디코딩
        subject_raw = mail_data["Subject"] or ""
        subject_parts = decode_header(subject_raw)
        subject = "".join(
            part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
            for part, encoding in subject_parts
        )
        # 본문 추출
        body = self.extract_body(mail_data)
        # 수신 이메일 로그 기록
        log_msg = f"Received email: Subject={subject}, Body={body}"
        print(log_msg)
        logger.info(log_msg)
        """
        필터링 장소
        
        필터링 기능 추가 필요 시 아래의 양식대로 아래쪽에 추가
        
        if self.함수():
            block_msg = "막는 이유"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected due to 이유"
        """
        # 1. 키워드 필터링
        if self.contains_blocked_keyword(subject, body):
            block_msg = "Blocked: Contains phishing/malicious content"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected due to content policy"
        # 2. 첨부파일 확장자 필터링
        if self.has_blocked_attachment(mail_data):
            block_msg = "Blocked: Contains dangerous attachment extension"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected due to dangerous attachment"
        # 3. MIME 매핑 테이블 검증
        if not self.validate_mime_mapping(mail_data):
            block_msg = "Blocked: MIME mapping validation failed"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected due to MIME mapping validation failure"
        """
        추가할 필터링은 이 자리에 추가해주시면 됩니다. 번호가 적혀있으니 순서대로 추가하면 됩니다.
        """
        # 필터링 통과 시 이메일 해시값 계산 (self.process_email 호출)
        body_hashes, attachment_hashes = self.process_email(envelope.content)
        logger.info(f"Email body hashes: {body_hashes}")
        if attachment_hashes:
            logger.info(f"Attachment hashes: {attachment_hashes}")
        # 안티바이러스 검사 수행 (self.antivirus_scan 호출)
        if not self.antivirus_scan(body_hashes, attachment_hashes):
            block_msg = "Blocked: Malicious content detected based on hash"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected due to malicious content"
        # 필터링 통과 시 Postfix로 릴레이 (다른 포트 사용)
        accept_msg = "Accepted: Email passed the filtering check"
        print(accept_msg)
        logger.info(accept_msg)
        relay_success = await self.relay_to_postfix(envelope)
        return "250 OK" if relay_success else "451 Temporary failure"
    
    def extract_body(self, mail_data):
        """본문 추출 함수: multipart인 경우 text/plain 파트만 추출"""
        if mail_data.is_multipart():
            body_parts = []
            for part in mail_data.walk():
                if part.get_content_type() == "text/plain" and not part.get_filename():
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_parts.append(payload.decode(errors="ignore"))
            return "\n".join(body_parts)
        else:
            payload = mail_data.get_payload(decode=True)
            return payload.decode(errors="ignore") if payload else ""
    
    def contains_blocked_keyword(self, subject, body):
        """이메일 제목과 본문에서 필터링할 키워드가 포함되었는지 검사"""
        content = (subject + " " + body).lower()
        return any(keyword in content for keyword in BLOCKED_KEYWORDS)
    
    def has_blocked_attachment(self, mail_data):
        """
        첨부파일의 확장자가 위험 확장자 목록에 있는지 검사.
        위험한 첨부파일이 있으면 True를 반환하고, 로그에 기록.
        """
        for part in mail_data.walk():
            filename = part.get_filename()
            if filename:
                ext = os.path.splitext(filename)[1].lower()
                if ext in BLOCKED_EXTENSIONS:
                    logger.info(f"Blocked attachment detected: {filename} with extension {ext}")
                    return True
        return False
    
    def validate_mime_mapping(self, mail_data):
        """
        첨부파일의 MIME 타입이 미리 정의된 MIME 매핑 테이블과 일치하는지 검증.
        매핑 테이블에 없는 확장자는 경고로 처리하며, 일치하지 않으면 False를 반환.
        """
        valid = True
        for part in mail_data.walk():
            filename = part.get_filename()
            if filename:
                ext = os.path.splitext(filename)[1].lower()
                expected_mime = MIME_MAPPING.get(ext)
                actual_mime = part.get_content_type()
                if expected_mime:
                    if expected_mime != actual_mime:
                        logger.error(f"MIME type mismatch for {filename}: expected {expected_mime}, got {actual_mime}")
                        valid = False
                else:
                    logger.warning(f"No MIME mapping found for {filename} with extension {ext}")
        return valid
    
    def process_email(self, message_data):
        """
        이메일 본문과 첨부파일(있다면)의 해시값을 계산하는 메서드.
        다중 해시 함수를 사용하여 MD5와 SHA-256 해시를 동시에 계산합니다.
        """
        msg = message_from_bytes(message_data, policy=default)
        # 이메일 본문 해시 계산
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_payload(decode=True)
                    break
        else:
            body_text = msg.get_payload(decode=True)
        if body_text:
            body_hashes = compute_multi_hash(body_text)
        else:
            body_hashes = {"MD5": "N/A", "SHA256": "N/A"}
        # 첨부파일 해시 계산 (있다면)
        attachment_hashes = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    attachment_data = part.get_payload(decode=True)
                    att_hashes = compute_multi_hash(attachment_data)
                    attachment_hashes.append(att_hashes)
        return body_hashes, attachment_hashes
    
    def antivirus_scan(self, body_hashes, attachment_hashes):
        """
        이메일 본문 및 첨부파일의 MD5 해시값이 악성코드 해시값과 일치하는지 검사합니다.
        악성코드가 감지되면 False, 안전하면 True를 반환합니다.
        """
        if body_hashes.get("MD5") in MALICIOUS_HASHES:
            print(f"[Filter] 이메일 본문이 악성코드와 일치함! 차단됨. (MD5: {body_hashes.get('MD5')})", file=sys.stderr)
            return False
        for idx, att in enumerate(attachment_hashes):
            if att.get("MD5") in MALICIOUS_HASHES:
                print(f"[Filter] 첨부파일 {idx+1}이 악성코드와 일치함! 차단됨. (MD5: {att.get('MD5')})", file=sys.stderr)
                return False
        return True
    
    async def relay_to_postfix(self, envelope):
        """필터링을 통과한 이메일을 Postfix 서버(10026 포트)로 릴레이"""
        try:
            reader, writer = await asyncio.open_connection(FILTERED_SMTP_HOST, FILTERED_SMTP_PORT)
            await self.send_smtp_data(reader, writer, envelope)
            writer.close()
            await writer.wait_closed()
            logger.info(f"Relayed email to Postfix at {FILTERED_SMTP_HOST}:{FILTERED_SMTP_PORT}")
            return True
        except Exception as e:
            logger.error(f"Failed to relay email: {e}")
            return False
    
    async def send_smtp_data(self, reader, writer, envelope):
        """SMTP 프로토콜을 사용하여 Postfix 서버에 이메일 전송"""
        async def send_cmd(cmd):
            writer.write(cmd.encode() + b"\r\n")
            await writer.drain()
            return await reader.read(1024)
        await send_cmd("EHLO filtering-server")
        await send_cmd(f"MAIL FROM:<{envelope.mail_from}>")
        for rcpt in envelope.rcpt_tos:
            await send_cmd(f"RCPT TO:<{rcpt}>")
        await send_cmd("DATA")
        writer.write(envelope.content + b"\r\n.\r\n")
        await writer.drain()
        await send_cmd("QUIT")

if __name__ == "__main__":
    controller = Controller(FilterHandler(), hostname="0.0.0.0", port=2500)
    logger.info("Python Filtering Server (No TLS) running on port 2500...")
    print("Python Filtering Server (No TLS) running on port 2500...")
    controller.start()
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
