from core.config.settings import settings


def main() -> None:
    print(f"{settings.app_name} — Adaptive Adversary Deception & Intelligence")
    print(f"Environment: {settings.environment}")
    print(f"Debug: {settings.debug}")


if __name__ == "__main__":
    main()
