from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_self_hosted_deploy_exposes_and_uses_target_environment() -> None:
    text = (ROOT / ".github/workflows/_vps-self-hosted-deploy.yml").read_text()

    assert "homologation_environment:" in text
    assert "default: false" in text
    assert "name: ${{ inputs.homologation_environment && 'homologation' || 'production' }}" in text
