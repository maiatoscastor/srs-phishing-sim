"""
Envio de emails de phishing simulado com tracking por token único.

Uso:
    python mailer.py --smtp smtp.gmail.com --port 587 \\
        --user remetente@gmail.com \\
        --server http://192.168.1.10:5000 \\
        --targets ../data/targets.json

A password SMTP é lida da variável de ambiente SMTP_PASSWORD.
Os resultados são guardados em data/logs/campaign.json.
"""

import argparse
import json
import os
import smtplib
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CAMPAIGN_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "logs", "campaign.json")
)
TARGETS_PATH_DEFAULT = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "targets.json")
)


def _load_targets(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        targets = json.load(fh)
    if not isinstance(targets, list):
        raise ValueError("targets.json deve ser uma lista JSON")
    return targets


def _save_campaign(entries: list[dict]) -> None:
    os.makedirs(os.path.dirname(CAMPAIGN_PATH), exist_ok=True)
    with open(CAMPAIGN_PATH, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2, ensure_ascii=False)


def _build_email(name: str, tracking_url: str) -> tuple[str, str]:
    """Devolve (subject, html_body)."""
    subject = "Ação necessária: verifique a sua conta Microsoft"
    html = f"""\
<!DOCTYPE html>
<html lang="pt">
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f2f2f2;font-family:'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table width="520" cellpadding="0" cellspacing="0"
               style="background:#fff;border-radius:4px;overflow:hidden;
                      box-shadow:0 2px 8px rgba(0,0,0,.1);">

          <!-- Header -->
          <tr>
            <td style="background:#0067b8;padding:20px 32px;">
              <span style="color:#fff;font-size:20px;font-weight:700;">Microsoft</span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:32px;">
              <p style="font-size:15px;color:#333;margin-bottom:16px;">
                Olá {name},
              </p>
              <p style="font-size:15px;color:#333;margin-bottom:16px;">
                Detetámos uma tentativa de acesso à sua conta Microsoft a partir
                de uma localização ou dispositivo não reconhecido.
              </p>
              <p style="font-size:15px;color:#333;margin-bottom:24px;">
                Para proteger a sua conta, pedimos que confirme a sua identidade
                o mais brevemente possível.
              </p>

              <!-- CTA -->
              <table cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
                <tr>
                  <td style="background:#0067b8;border-radius:2px;">
                    <a href="{tracking_url}"
                       style="display:inline-block;padding:12px 28px;
                              color:#fff;font-size:15px;font-weight:600;
                              text-decoration:none;">
                      Verificar conta
                    </a>
                  </td>
                </tr>
              </table>

              <p style="font-size:13px;color:#666;margin-bottom:8px;">
                Se não reconhece esta atividade, pode ignorar este email.
                A sua conta permanecerá segura.
              </p>
              <p style="font-size:13px;color:#666;">
                Este link expira em 24 horas.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#f5f5f5;padding:16px 32px;
                       border-top:1px solid #eee;">
              <p style="font-size:12px;color:#999;margin:0;">
                Microsoft Corporation · One Microsoft Way · Redmond, WA 98052
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""
    return subject, html


def send_campaign(
    targets: list[dict],
    server_url: str,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_address: str,
) -> list[dict]:
    server_url = server_url.rstrip("/")
    campaign: list[dict] = []

    with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login(smtp_user, smtp_password)

        for target in targets:
            name = target.get("name", "Utilizador")
            email = target.get("email", "")
            if not email:
                print(f"  [SKIP] Alvo sem email: {target}")
                continue

            token = str(uuid.uuid4())
            tracking_url = f"{server_url}/track/{token}"
            subject, html_body = _build_email(name, tracking_url)

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_address
            msg["To"] = email
            msg.attach(MIMEText(html_body, "html", "utf-8"))

            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "name": name,
                "email": email,
                "token": token,
                "sent": False,
                "error": None,
            }

            try:
                smtp.sendmail(smtp_user, [email], msg.as_string())
                entry["sent"] = True
                print(f"  [OK]   {email} (token: {token[:8]}…)")
            except Exception as exc:
                entry["error"] = str(exc)
                print(f"  [FAIL] {email}: {exc}")

            campaign.append(entry)

    return campaign


def main() -> None:
    parser = argparse.ArgumentParser(description="Enviar campanha de phishing simulado")
    parser.add_argument("--smtp", required=True, help="Servidor SMTP (ex: smtp.gmail.com)")
    parser.add_argument("--port", type=int, default=587, help="Porta SMTP (default: 587)")
    parser.add_argument("--user", required=True, help="Utilizador SMTP")
    parser.add_argument("--from", dest="from_addr", default=None,
                        help="Endereço 'From' (default: igual ao --user)")
    parser.add_argument("--server", required=True,
                        help="URL base do servidor de ataque (ex: http://192.168.1.10:5000)")
    parser.add_argument("--targets", default=TARGETS_PATH_DEFAULT,
                        help=f"Caminho para targets.json (default: {TARGETS_PATH_DEFAULT})")
    args = parser.parse_args()

    password = os.environ.get("SMTP_PASSWORD")
    if not password:
        import getpass
        password = getpass.getpass("Password SMTP: ")

    from_address = args.from_addr or args.user

    print(f"\nA carregar alvos de: {args.targets}")
    targets = _load_targets(args.targets)
    print(f"Alvos encontrados: {len(targets)}")
    print(f"Servidor de tracking: {args.server}")
    print(f"A enviar emails...\n")

    campaign = send_campaign(
        targets=targets,
        server_url=args.server,
        smtp_host=args.smtp,
        smtp_port=args.port,
        smtp_user=args.user,
        smtp_password=password,
        from_address=from_address,
    )

    _save_campaign(campaign)
    sent = sum(1 for e in campaign if e["sent"])
    print(f"\nCampanha concluída: {sent}/{len(campaign)} emails enviados.")
    print(f"Registo guardado em: {CAMPAIGN_PATH}")


if __name__ == "__main__":
    main()
