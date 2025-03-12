import asyncio
import logging
import os
import re
import io
import zipfile
import tarfile
from email.parser import BytesParser
from email.header import decode_header
from aiosmtpd.controller import Controller
from urllib.parse import urlparse
from html import unescape
import sys
import smtplib
import hashlib
from email.policy import default
from email import message_from_bytes
import bleach

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

MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 첨부 파일 최대 크기: 10MB (단위: 바이트)

# 악성코드 MD5 해시값 리스트
MALICIOUS_HASHES = {
    "c095272b8480b9033a7a1d5b2fa1cf84",
    "29b3d6974d2c36be6715022bc04dee09",
    "75ef3825e165902a56d2e19d5741bf4c"
}

# 허용 도메인 및 경로 패턴 목록 (필요에 따라 추가)
ALLOWED_DOMAIN_PATHS = {
    "www.gothroughsecurity.store": ["/wordpress/"],
    "ssl.pstatic.net": ["/"],
    "dmfiles.naver.net": ["/"],
    "bigfile.mail.naver.com": ["/download"],
    "mybox.naver.com": ["/"],
    "mail.naver.com": ["/"]
}

class FilterHandler:
    def decode_mime_words(self, s):
        decoded_fragments = decode_header(s)
        result = []
        for fragment, encoding in decoded_fragments:
            if isinstance(fragment, bytes):
                encoding = encoding if encoding and encoding.lower() != "unknown-8bit" else "utf-8"
                result.append(fragment.decode(encoding, errors="replace"))
            else:
                result.append(fragment)
        return "".join(result)

    def sanitize_html_content(self, html_content):
        """
        bleach 라이브러리를 이용해 HTML을 sanitize합니다.
        허용된 태그와 속성만 남기고 나머지는 제거합니다.
        """
        allowed_tags = [
            'p', 'br', 'b', 'i', 'u', 'strong', 'em',
            'ul', 'ol', 'li', 'span', 'div', 'img'
        ]
        allowed_attributes = {
            'img': ['alt', 'title'],
            'table': ['border', 'width', 'height'],
            'tr' : ['colspan', 'rowspan', 'align', 'valign'],
            'td': ['colspan', 'rowspan', 'align', 'valign'],
            'th': ['colspan', 'rowspan', 'align', 'valign'],
            'span': ['style'],
            'div': ['style'],
            '*': ['class']
        }
        cleaned_html = bleach.clean(
            html_content,
            tags=allowed_tags,
            attributes=allowed_attributes,
            strip=True
        )
        return cleaned_html

    async def handle_DATA(self, server, session, envelope):
        logger.debug("handle_DATA 호출됨.")
        # 이메일 파싱
        mail_data = BytesParser().parsebytes(envelope.content)
        logger.debug("이메일 내용 파싱 완료.")

        # Subject 디코딩
        subject_raw = mail_data["Subject"] or ""
        subject = self.decode_mime_words(subject_raw)
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
                filename = self.decode_mime_words(filename)
            content_type = part.get_content_type()
            logger.info(f"Part {idx}: filename={filename}, content_type={content_type}")

        # 1. 키워드 필터링
        if self.contains_blocked_keyword(subject, body):
            block_msg = "Blocked: Contains phishing/malicious content"
            print(block_msg)
            logger.info(block_msg)
            return  "554 Message rejected"

        # 2. 첨부파일 확장자 필터링
        if self.has_blocked_attachment(mail_data):
            block_msg = "Blocked: Contains dangerous attachment extension"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected"

        # 3. MIME 매핑 테이블 검증
        if not self.validate_mime_mapping(mail_data):
            block_msg = "Blocked: MIME mapping validation failed"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected"

        # 4. URL 필터링
        combined_text = subject + " " + body
        urls_valid = self.validate_urls_in_text(combined_text)
        if not urls_valid:
            block_msg = "Blocked: Contains untrusted URL"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected"

        if self.has_large_attachment(mail_data):
            block_msg = f"Blocked: Attachment exceeds size limit of {MAX_ATTACHMENT_SIZE / (1024 * 1024)} MB"
            print(block_msg)
            logger.info(block_msg)
            return "554 Message rejected"

        # 5. 압축 포맷 파일 추출 및 내부 파일 검사
        extracted_files = self.extract_compressed_files(mail_data)
        if extracted_files:
            logger.info(f"추출된 압축 파일 내 파일 목록: {list(extracted_files.keys())}")
            for fname, content in extracted_files.items():
                # 추가로 악성 코드 키워드 검색 등 검사
                file_type = self.identify_file_type(fname, content)[0]
                logger.debug(f"파일 {fname} 식별된 타입: {file_type}")
                content_str = content.decode(errors='ignore') if isinstance(content, bytes) else content
                if self.search_malicious_code_keywords(content_str):
                    block_msg = f"Blocked: Extracted file {fname} contains malicious code patterns"
                    logger.info(block_msg)
                    return "554 Message rejected"

        # 7. HTML Sanitization: 본문에 HTML 태그가 포함된 경우 bleach를 이용해 정화
        if "<html" in body.lower() or "<div" in body.lower() or "<span" in body.lower():
            sanitized_body = self.sanitize_html_content(body)
            logger.debug("Sanitized HTML content: " + sanitized_body[:100] + "...")
            body = sanitized_body

        # 9. 이메일 해시값 계산
        body_hashes, attachment_hashes = self.process_email(envelope.content)
        logger.info(f"Email body hashes: {body_hashes}")
        if attachment_hashes:
            logger.info(f"Attachment hashes: {attachment_hashes}")
        if not self.antivirus_scan(body_hashes, attachment_hashes):
            block_msg = "Blocked: Malicious content detected based on hash"
            return "554 Message rejected"

        # 필터링 통과 시 Postfix로 릴레이 (추후 안티바이러스 기능 등 추가 가능)
        accept_msg = "Accepted: Email passed the filtering check"
        print(accept_msg)
        logger.info(accept_msg)
        relay_success = await self.relay_to_postfix(envelope)
        return "250 OK" if relay_success else "451 Temporary failure"

    def extract_body(self, mail_data):
        """본문 추출 함수: multipart인 경우 text/plain 및 text/html 파트를 추출"""
        logger.debug("본문 추출 시작")
        if mail_data.is_multipart():
            body_parts = []
            for idx, part in enumerate(mail_data.walk()):
                if part.get_content_type() in ["text/plain", "text/html"] and not part.get_filename():
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset()
                        if charset is None or charset.lower() == "unknown-8bit":
                            charset = "utf-8"
                        decoded_payload = payload.decode(charset, errors="replace")
                        body_parts.append(decoded_payload)
                        logger.debug(f"Part {idx} ({part.get_content_type()}) 추출됨: {decoded_payload[:50]}...")
            body_text = "\n".join(body_parts)
            logger.debug("multipart 본문 추출 완료")
            return body_text
        else:
            payload = mail_data.get_payload(decode=True)
            if payload:
                charset = mail_data.get_content_charset()
                if charset is None or charset.lower() == "unknown-8bit":
                    charset = "utf-8"
                body_text = payload.decode(charset, errors="replace")
            else:
                body_text = ""
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
        """
        logger.debug("첨부파일 검사 시작")
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = self.decode_mime_words(filename)
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
        """
        logger.debug("MIME 매핑 검증 시작")
        valid = True
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = self.decode_mime_words(filename)
                ext, expected_mime = self.identify_file_type(filename, part.get_payload(decode=True))
                actual_mime = part.get_content_type()
                logger.debug(
                    f"Part {idx} - 파일명: {filename}, 확장자: {ext}, 예상 MIME: {expected_mime}, 실제 MIME: {actual_mime}")
                if expected_mime:
                    if expected_mime != actual_mime:
                        logger.error(f"MIME type mismatch for {filename}: expected {expected_mime}, got {actual_mime}")
                        valid = False
                else:
                    logger.warning(f"No MIME mapping found for {filename} with extension {ext}")
        logger.debug("MIME 매핑 검증 완료")
        return valid

    def extract_urls(self, text):
        """
        정규표현식을 사용하여 텍스트 내의 URL을 추출
        """
        url_pattern = r'(https?://[^\s<>"]+)'
        return re.findall(url_pattern, text)

    def validate_urls_in_text(self, text):
        logger.debug("URL 검증 시작")
        urls = self.extract_urls(text)
        for url in urls:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                logger.debug(f"URL 오류 (스킴): {url}")
                return False
            allowed_paths = ALLOWED_DOMAIN_PATHS.get(parsed.netloc.lower())
            if not allowed_paths:
                logger.debug(f"허용되지 않은 도메인: {url}")
                return False
            if not any(parsed.path.startswith(prefix) for prefix in allowed_paths):
                logger.debug(f"허용되지 않은 하위 도메인: {url}")
                return False
        return True


    def has_large_attachment(self, mail_data):
        """
        첨부 파일이 최대 크기 제한을 초과하는지 검사.
        """
        logger.debug("첨부파일 크기 확인 시작")
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = self.decode_mime_words(filename)
                content_disposition = part.get("Content-Disposition", "").lower()
                if "attachment" in content_disposition:
                    file_size = len(part.get_payload(decode=True))
                    logger.debug(f"Part {idx} 파일명: {filename}, 크기: {file_size} 바이트")
                    if file_size > MAX_ATTACHMENT_SIZE:
                        logger.info(
                            f"Blocked attachment: {filename} exceeds size limit of {MAX_ATTACHMENT_SIZE / (1024 * 1024)} MB")
                        return True
        logger.debug("첨부파일 크기 확인 완료")
        return False

    def extract_compressed_files(self, mail_data):
        extracted_files = {}
        COMPRESSED_EXTENSIONS = ['.zip', '.tar', '.gz', '.rar']
        for idx, part in enumerate(mail_data.walk()):
            filename = part.get_filename() or part.get_param("name")
            if filename:
                filename = self.decode_mime_words(filename)
                ext = os.path.splitext(filename)[1].lower()
                if ext in COMPRESSED_EXTENSIONS:
                    payload = part.get_payload(decode=True)
                    if payload:
                        logger.debug(f"압축 파일 {filename} 추출 시도")
                        try:
                            if ext == ".zip":
                                with zipfile.ZipFile(io.BytesIO(payload)) as z:
                                    for info in z.infolist():
                                        with z.open(info) as extracted:
                                            file_content = extracted.read()
                                            extracted_files[info.filename] = file_content
                                            logger.debug(f"압축 파일 {filename} 내 파일 추출: {info.filename}")
                                            # 여기서 ZIP 내부 파일의 확장자 검사 추가
                                            internal_ext = os.path.splitext(info.filename)[1].lower()
                                            if internal_ext in BLOCKED_EXTENSIONS:
                                                logger.info(f"Blocked file inside ZIP: {info.filename}")
                                                return {}  # ZIP 전체를 차단
                            elif ext in [".tar", ".gz"]:
                                with tarfile.open(fileobj=io.BytesIO(payload)) as t:
                                    for member in t.getmembers():
                                        if member.isfile():
                                            extracted_file = t.extractfile(member)
                                            if extracted_file:
                                                file_content = extracted_file.read()
                                                extracted_files[member.name] = file_content
                                                logger.debug(f"압축 파일 {filename} 내 파일 추출: {member.name}")
                                                # TAR 내부 파일 확장자 검사
                                                internal_ext = os.path.splitext(member.name)[1].lower()
                                                if internal_ext in BLOCKED_EXTENSIONS:
                                                    logger.info(f"Blocked file inside TAR: {member.name}")
                                                    return {}
                        except Exception as e:
                            logger.error(f"압축 파일 {filename} 추출 실패: {e}")
        return extracted_files



    def identify_file_type(self, filename, file_content):
        """
        파일의 콘텐츠와 파일명을 바탕으로 파일 타입을 식별.
        """
        ext = os.path.splitext(filename)[1].lower()
        file_type = MIME_MAPPING.get(ext, "application/octet-stream")
        logger.debug(f"파일 타입 식별: {filename} -> {file_type}")
        return ext, file_type

    def search_malicious_code_keywords(self, content):
        """
        악성 코드 관련 키워드가 포함되어 있는지 검사.
        """
        malicious_keywords = [
            "eval(", "exec(", "system(", "passthru", "base64_decode", "onerror", "onload", "document.write", "<script>"
        ]
        for keyword in malicious_keywords:
            if keyword.lower() in content.lower():
                logger.debug(f"악성 코드 키워드 발견: {keyword}")
                return True
        return False

    def compute_md5(self, data: bytes) -> str:
        """MD5 해시값을 계산하여 반환."""
        md5_hash = hashlib.md5()
        md5_hash.update(data)
        return md5_hash.hexdigest()

    def compute_sha256(self, data: bytes) -> str:
        """SHA-256 해시값을 계산하여 반환."""
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        return sha256_hash.hexdigest()

    def compute_multi_hash(self, data: bytes) -> dict:
        """
        MD5와 SHA-256 해시를 같이 반환.
        """
        return {
            "MD5": self.compute_md5(data),
            "SHA256": self.compute_sha256(data)
        }

    def process_email(self, message_data):
        """
        이메일 본문과 첨부파일의 해시값을 계산하는 메서드.
        """
        msg = message_from_bytes(message_data, policy=default)
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body_text = part.get_payload(decode=True)
                    break
        else:
            body_text = msg.get_payload(decode=True)

        if body_text:
            body_hashes = self.compute_multi_hash(body_text)
        else:
            body_hashes = {"MD5": "N/A", "SHA256": "N/A"}
        attachment_hashes = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    attachment_data = part.get_payload(decode=True)
                    att_hashes = self.compute_multi_hash(attachment_data)
                    attachment_hashes.append(att_hashes)
        return body_hashes, attachment_hashes

    def antivirus_scan(self, body_hashes, attachment_hashes):
        """
        이메일 본문 및 첨부파일의 MD5, SHA256 해시값이 악성코드 해시값과 일치하는지 검사.
        """
        if body_hashes.get("MD5") in MALICIOUS_HASHES or body_hashes.get("SHA256") in MALICIOUS_HASHES:
            logger.info(
                f"[Filter] 이메일 본문이 악성코드와 일치함! 차단됨. (MD5: {body_hashes.get('MD5')}, SHA256: {body_hashes.get('SHA256')})")
            return False
        for idx, att in enumerate(attachment_hashes):
            if att.get("MD5") in MALICIOUS_HASHES or att.get("SHA256") in MALICIOUS_HASHES:
                logger.info(
                    f"[Filter] 첨부파일 {idx + 1}이 악성코드와 일치함! 차단됨. (MD5: {att.get('MD5')}, SHA256: {att.get('SHA256')})")
                return False
        return True

    async def relay_to_postfix(self, envelope):
        """필터링을 통과한 이메일을 Postfix 서버(10025 포트)로 릴레이"""
        relay_host = "192.168.0.151"  # 메일 서버 IP
        relay_port = 10025  # Postfix 포트

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