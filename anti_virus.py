import asyncio
import logging
import os
from email.parser import BytesParser
from email.header import decode_header
from aiosmtpd.controller import Controller

#############
import sys
import smtplib
import hashlib
from email.policy import default
from email import message_from_bytes



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
##########################################

# 로그 설정: DEBUG 레벨로 모든 세부 정보를 기록
logging.basicConfig(filename="/var/log/filtering_server.log", level=logging.DEBUG,
                    format="%(asctime)s - %(levelname)s - %(message)s")
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

def decode_mime_words(s):
    """MIME 인코딩된 문자열을 디코딩하는 함수"""
    decoded_fragments = decode_header(s)
    return ''.join(
        fragment.decode(encoding or 'utf-8') if isinstance(fragment, bytes) else fragment
        for fragment, encoding in decoded_fragments
    )

class FilterHandler:
    async def handle_DATA(self, server, session, envelope):
        logger.debug("handle_DATA 호출됨.")
        # 이메일 파싱
        mail_data = BytesParser().parsebytes(envelope.content)
        logger.debug("이메일 파싱 완료.")

        # Subject 디코딩
        subject_raw = mail_data["Subject"] or ""
        subject_parts = decode_header(subject_raw)
        subject = "".join(
            part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
            for part, encoding in subject_parts
        )
        logger.debug(f"디코딩된 Subject: {subject}")

        # 본문 추출
        body = self.extract_body(mail_data)
        logger.debug(f"추출된 본문: {body[:100]}...")
        log_msg = f"Received email: Subject={subject}, Body Length={len(body)}"
        print(log_msg)
        logger.info(log_msg)

        # 각 파트의 정보를 상세히 기록
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = decode_mime_words(filename)
            content_type = part.get_content_type()
            logger.debug(f"Part {idx}: filename={filename}, content_type={content_type}")

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






        # 필터링 통과 시 Postfix로 릴레이 (추후 안티바이러스 기능 등 추가 가능)
        accept_msg = "Accepted: Email passed the filtering check"
        print(accept_msg)
        logger.info(accept_msg)
        relay_success = await self.relay_to_postfix(envelope)
        return "250 OK" if relay_success else "451 Temporary failure"

    def extract_body(self, mail_data):
        """본문 추출 함수: multipart인 경우 text/plain 파트만 추출"""
        logger.debug("본문 추출 시작")
        if mail_data.is_multipart():
            body_parts = []
            for idx, part in enumerate(mail_data.walk()):
                if part.get_content_type() == "text/plain" and not part.get_filename():
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded_payload = payload.decode(errors="ignore")
                        body_parts.append(decoded_payload)
                        logger.debug(f"Part {idx} (text/plain) 추출됨: {decoded_payload[:50]}...")
            body_text = "\n".join(body_parts)
            logger.debug("multipart 본문 추출 완료")
            return body_text
        else:
            payload = mail_data.get_payload(decode=True)
            body_text = payload.decode(errors="ignore") if payload else ""
            logger.debug("단일 파트 본문 추출 완료")
            return body_text

    def contains_blocked_keyword(self, subject, body):
        """이메일 제목과 본문에서 필터링할 키워드가 포함되었는지 검사"""
        content = (subject + " " + body).lower()
        for keyword in BLOCKED_KEYWORDS:
            if keyword in content:
                logger.debug(f"차단 키워드 '{keyword}' 발견됨")
                return True
        return False

    def has_blocked_attachment(self, mail_data):
        """
        첨부파일의 확장자가 위험 확장자 목록에 있는지 검사.
        MIME 인코딩된 파일명은 먼저 디코딩한 후 확장자 추출.
        위험한 첨부파일이 있으면 True를 반환하고, 해당 사실을 로그에 기록함.
        """
        logger.debug("첨부파일 검사 시작")
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = decode_mime_words(filename)
                logger.debug(f"Part {idx} 디코딩된 파일명: {filename}")
                ext = os.path.splitext(filename)[1].lower()
                logger.debug(f"Part {idx} 확장자 확인: {ext}")
                if ext in BLOCKED_EXTENSIONS:
                    logger.info(f"Blocked attachment detected: {filename} with extension {ext}")
                    return True
            else:
                logger.debug(f"Part {idx} 파일명 확인: {filename}")
        logger.debug("위험한 첨부파일 없음")
        return False

    def validate_mime_mapping(self, mail_data):
        """
        첨부파일의 MIME 타입이 미리 정의된 MIME 매핑 테이블과 일치하는지 검증.
        매핑 테이블에 없는 확장자는 경고로 처리하며, 일치하지 않으면 False를 반환.
        """
        logger.debug("MIME 매핑 검증 시작")
        valid = True
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = decode_mime_words(filename)
                ext = os.path.splitext(filename)[1].lower()
                expected_mime = MIME_MAPPING.get(ext)
                actual_mime = part.get_content_type()
                logger.debug(f"Part {idx} - 파일명: {filename}, 확장자: {ext}, 예상 MIME: {expected_mime}, 실제 MIME: {actual_mime}")
                if expected_mime:
                    if expected_mime != actual_mime:
                        logger.error(f"MIME type mismatch for {filename}: expected {expected_mime}, got {actual_mime}")
                        valid = False
                else:
                    logger.warning(f"No MIME mapping found for {filename} with extension {ext}")
        logger.debug("MIME 매핑 검증 완료")
        return valid

    async def relay_to_postfix(self, envelope):
        """필터링을 통과한 이메일을 Postfix 서버(10025 포트)로 릴레이"""
        relay_host = "192.168.0.151"  # 메일 서버 IP
        relay_port = 10025          # Postfix가 필터링 후 메일을 받을 포트

        try:
            logger.debug(f"Postfix로 릴레이 시도: {relay_host}:{relay_port}")
            reader, writer = await asyncio.open_connection(relay_host, relay_port)
            await self.send_smtp_data(reader, writer, envelope)
            writer.close()
            await writer.wait_closed()
            logger.info(f"Relayed email to Postfix at {relay_host}:{relay_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to relay email: {e}")
            return False

    async def send_smtp_data(self, reader, writer, envelope):
        """SMTP 프로토콜을 사용하여 Postfix 서버에 이메일 전송"""
        async def send_cmd(cmd):
            logger.debug(f"SMTP 명령 전송: {cmd}")
            writer.write(cmd.encode() + b"\r\n")
            await writer.drain()
            response = await reader.read(1024)
            logger.debug(f"SMTP 응답: {response.decode(errors='ignore').strip()}")
            return response

        await send_cmd("EHLO filtering-server")
        await send_cmd(f"MAIL FROM:<{envelope.mail_from}>")
        for rcpt in envelope.rcpt_tos:
            await send_cmd(f"RCPT TO:<{rcpt}>")
        await send_cmd("DATA")
        writer.write(envelope.content + b"\r\n.\r\n")
        await writer.drain()
        await send_cmd("QUIT")

if __name__ == "__main__":
    # 필터링 서버 시작
    controller = Controller(FilterHandler(), hostname="0.0.0.0", port=2500)
    logger.info("Python Filtering Server (No TLS) running on port 2500...")
    print("Python Filtering Server (No TLS) running on port 2500...")
    controller.start()

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass

