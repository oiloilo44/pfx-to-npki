import os
import sys
import subprocess
import re
import base64
import pypinksign
from getpass import getpass
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

def find_openssl():
    """내장된 OpenSSL 실행 파일 경로만 반환합니다."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_openssl = os.path.join(script_dir, "openssl_bin", "openssl.exe")
    
    if os.path.exists(local_openssl):
        return local_openssl
    return None

def find_pfx_file(directory):
    for f in os.listdir(directory):
        if f.lower().endswith(".pfx") or f.lower().endswith(".p12"):
            return os.path.join(directory, f)
    return None

def extract_vid_via_openssl(pfx_path, password, openssl_path):
    print(f"[Info] OpenSSL을 사용하여 PFX 내부 구조 분석 중...")
    cmd = [openssl_path, "pkcs12", "-in", pfx_path, "-info", "-nodes", "-passin", f"pass:{password}"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if result.returncode != 0:
            print(f"[Warning] OpenSSL 실행 상태: {result.returncode}")
            if "Mac verify error" in result.stderr:
                print(" -> 비밀번호가 올바르지 않은 것 같습니다.")
                
        dump_data = result.stdout
        vid_oid = "1.2.410.200004.10.1.1.3"
        
        if vid_oid in dump_data:
            print("[Success] VID OID(1.2.410.200004.10.1.1.3) 발견!")
            parts = dump_data.split(vid_oid)
            context = parts[1][:500] 
            match = re.search(r'((?:[0-9A-Fa-f]{2}[:\s]*){20})', context)
            if match:
                hex_str = match.group(1).replace(':', '').replace(' ', '').replace('\n', '').strip()
                print(f"[Success] VID Hex 추출 완료: {hex_str}")
                return bytes.fromhex(hex_str)
            else:
                print("[Error] OID 발견, but Hex 패턴 매칭 실패")
        else:
            print("[Warning] PFX 덤프에서 VID OID를 찾을 수 없습니다.")
            
    except Exception as e:
        print(f"[Error] OpenSSL 실행 예외: {e}")
        
    return None

def get_dn_string(name):
    """X.509 Name 객체를 NPKI 폴더명 형식(cn=...,ou=...)으로 변환"""
    parts = []
    # RDN을 역순으로 순회 (Leaf -> Root)
    for attr in reversed(list(name)):
        tag = "unknown"
        if attr.oid == NameOID.COMMON_NAME: tag = "cn"
        elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME: tag = "ou"
        elif attr.oid == NameOID.ORGANIZATION_NAME: tag = "o"
        elif attr.oid == NameOID.COUNTRY_NAME: tag = "c"
        elif attr.oid == NameOID.SERIAL_NUMBER: tag = "serialNumber"
        elif attr.oid == NameOID.LOCALITY_NAME: tag = "l"
        elif attr.oid == NameOID.STATE_OR_PROVINCE_NAME: tag = "st"
        else: tag = attr.oid._name if hasattr(attr.oid, '_name') else "oid"
        
        parts.append(f"{tag}={attr.value}")
    return ",".join(parts)

def convert_pfx_to_npki(pfx_path, password):
    base_dir = os.path.dirname(os.path.abspath(pfx_path))
    
    print(f"\n=== 변환 시작 ===")
    print(f"파일: {pfx_path}")
    
    # 1. OpenSSL VID Extraction
    openssl_bin = find_openssl()
    if not openssl_bin:
        print("[Error] 'openssl_bin' 폴더를 찾을 수 없습니다.")
        input("엔터를 누르면 종료합니다...")
        return

    vid_bytes = extract_vid_via_openssl(pfx_path, password, openssl_bin)
    
    if not vid_bytes:
        print("\n[Warning] VID 추출 실패.")
        choice = input("VID 없이 진행하시겠습니까? (y/n): ")
        if choice.lower() != 'y': return

    # 2. Cryptography Conversion & NPKI Folder Creation
    try:
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()
        
        pk, cert, _ = pkcs12.load_key_and_certificates(pfx_data, password.encode(), default_backend())
        
        # NPKI 폴더 구조 생성
        # 구조: base_dir \ NPKI \ [CA_Organization] \ User \ [Subject_DN]
        subject_dn = get_dn_string(cert.subject)
        try:
            ca_org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        except:
            ca_org = "UnknownCA"
            
        npki_dir = os.path.join(base_dir, "NPKI", ca_org, "User", subject_dn)
        
        if not os.path.exists(npki_dir):
            os.makedirs(npki_dir)
            print(f"\n[Created] NPKI 폴더 생성: ...\\NPKI\\{ca_org}\\User\\{subject_dn[:20]}...")
        
        print(f"출력 경로: {npki_dir}\n")

        # Save Cert
        cert_der = cert.public_bytes(Encoding.DER)
        cert_path = os.path.join(npki_dir, "signCert.der")
        with open(cert_path, "wb") as f:
            f.write(cert_der)
        print(f"[Saved] 인증서 저장 완료: signCert.der")
        
        # Save Key
        key_der = pk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        key_b64 = base64.b64encode(key_der).decode('utf-8')
        
        if vid_bytes:
            print("[Processing] 추출된 VID 주입 중...")
            plain_for_enc = pypinksign.inject_rand_in_plain_prikey(key_b64, vid_bytes)
        else:
            plain_for_enc = key_b64
            
        print("[Processing] 개인키 암호화 (SEED-CBC)...")
        enc_b64 = pypinksign.encrypt_decrypted_prikey(plain_for_enc, password.encode(), iter_cnt=2048)
        enc_der = base64.b64decode(enc_b64)
        
        key_path = os.path.join(npki_dir, "signPri.key")
        with open(key_path, "wb") as f:
            f.write(enc_der)
        print(f"[Saved] 개인키 저장 완료: signPri.key")
        
        # Validation
        if vid_bytes and len(enc_der) >= 1300:
            print("\n[Success] 모든 변환 및 NPKI 폴더 생성이 완료되었습니다.")
        else:
            print("\n[Done] 변환 완료 (주의: VID 확인 필요)")

    except Exception as e:
        print(f"\n[Fatal Error] 변환 실패: {e}")
    
    input("\n엔터를 누르면 종료합니다...")

import msvcrt

def get_password_with_asterisk(prompt="비밀번호 입력: "):
    print(prompt, end='', flush=True)
    buf = []
    while True:
        ch = msvcrt.getch()
        if ch in {b'\r', b'\n'}: # Enter
            print('')
            break
        elif ch == b'\x08': # Backspace
            if buf:
                buf.pop()
                # 커서를 뒤로, 공백 출력, 다시 뒤로 (글자 지움)
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        elif ch == b'\x03': # Ctrl+C
            raise KeyboardInterrupt
        else:
            # 특수키(0x00, 0xe0) 처리 (화살표 등 무시)
            if ch in {b'\x00', b'\xe0'}:
                msvcrt.getch() # 나머지 바이트 읽고 버림
                continue
                
            try:
                char = ch.decode('cp949') # 윈도우 콘솔 인코딩 대응
                buf.append(char)
                sys.stdout.write('*')
                sys.stdout.flush()
            except:
                pass
    return ''.join(buf)

def main():
    print("==================================================")
    print("      홈택스 호환 NPKI 변환기 (PFX -> NPKI 폴더)")
    print("==================================================")
    
    default_dir = os.path.dirname(os.path.abspath(__file__))
    auto_pfx = find_pfx_file(default_dir)
    
    pfx_path = input(f"PFX 파일 경로 입력 (빈칸 시 자동 검색: {os.path.basename(auto_pfx) if auto_pfx else '없음'}): ").strip()
    
    if not pfx_path:
        if auto_pfx: pfx_path = auto_pfx
        else:
            print("파일을 찾을 수 없습니다.")
            input("종료..."); return
            
    pfx_path = pfx_path.strip('"')
    
    if not os.path.isfile(pfx_path):
        print(f"파일이 존재하지 않습니다: {pfx_path}")
        input("종료..."); return
    
    # 비밀번호 입력 (* 표시)
    try:
        password = get_password_with_asterisk("비밀번호 입력: ")
    except KeyboardInterrupt:
        print("\n취소되었습니다.")
        return

    convert_pfx_to_npki(pfx_path, password)

if __name__ == "__main__":
    main()
