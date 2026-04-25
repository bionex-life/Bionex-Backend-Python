import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from app.config import get_settings

settings = get_settings()


def send_verification_email(to_email: str, to_name: str, token: str) -> bool:
    """Send verification email via Brevo. Returns True on success."""
    
    # Step 1 — configure Brevo with your API key
    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = settings.BREVO_API_KEY

    # Step 2 — create the API client
    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    # Step 3 — build the verification link
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"

    # Step 4 — build the email
    email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email, "name": to_name}],
        sender={"email": settings.BREVO_SENDER_EMAIL, "name": settings.BREVO_SENDER_NAME},
        subject="Verify your Bionex account",
        html_content=f"""
        <h2>Welcome to Bionex, {to_name}!</h2>
        <p>Click below to verify your email.</p>
        <a href="{verify_url}">Verify Email</a>
        <p>This link expires in 24 hours.</p>
        """,
    )

    # Step 5 — send it
    try:
        api_instance.send_transac_email(email)
        return True
    except ApiException as e:
        print(f"Brevo error: {e}")
        return False