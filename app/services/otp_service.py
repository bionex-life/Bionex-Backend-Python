import random
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from twilio.rest import Client
from app.config import get_settings

settings = get_settings()


def generate_otp() -> str:
    """Generate a secure 6-digit OTP."""
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def send_otp_sms(phone_number: str, otp: str) -> bool:
    """Send OTP via Twilio SMS. Returns True on success."""
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        client.messages.create(
            body=(
                f"🔐 Your Bionex OTP is: {otp}\n"
                f"Valid for {settings.OTP_EXPIRE_SECONDS} seconds. "
                f"Do not share this with anyone.\n"
                f"Also check your email to click the verification link."
            ),
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number,
        )
        return True
    except Exception as e:
        print(f"Twilio SMS error: {e}")
        return False


def send_otp_email(to_email: str, to_name: str, otp: str) -> bool:
    """Send OTP via Brevo email. Returns True on success."""
    try:
        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key["api-key"] = settings.BREVO_API_KEY

        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

        email = sib_api_v3_sdk.SendSmtpEmail(
            to=[{"email": to_email, "name": to_name}],
            sender={
                "email": settings.BREVO_SENDER_EMAIL,
                "name": settings.BREVO_SENDER_NAME,
            },
            subject="🔐 Your Bionex OTP Code",
            html_content=f"""
            <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 32px; border: 1px solid #e5e7eb; border-radius: 10px;">
                <h2 style="color: #1d4ed8;">Hello, {to_name}! 👋</h2>
                <p style="font-size: 15px; color: #374151;">
                    Use the OTP below to verify your identity on <strong>Bionex</strong>.
                </p>
                <div style="background: #f0f4ff; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0;">
                    <span style="font-size: 36px; font-weight: bold; letter-spacing: 10px; color: #1d4ed8;">{otp}</span>
                </div>
                <p style="font-size: 13px; color: #6b7280;">
                    ⏱️ This OTP is valid for <strong>{settings.OTP_EXPIRE_SECONDS} seconds</strong> only.
                    Do not share it with anyone.
                </p>
                <p style="font-size: 13px; color: #6b7280;">
                    Also, please click the verification link in the separate email we sent you
                    to fully activate your account. 🔗
                </p>
                <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 24px 0;" />
                <p style="font-size: 12px; color: #9ca3af;">
                    If you did not request this, please ignore this email.
                </p>
            </div>
            """,
        )

        api_instance.send_transac_email(email)
        return True
    except ApiException as e:
        print(f"Brevo OTP email error: {e}")
        return False