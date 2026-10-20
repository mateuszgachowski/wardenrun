public enum WardenrunVersion {
    public static let current = "0.1.0-dev"
}

public enum Usage {
    public static let text = """
    wardenrun \(WardenrunVersion.current): let an AI agent use a Vaultwarden secret without being handed it.

    usage:
      wardenrun run <item> [--env VAR=field]... [--file VAR=field]... [--stdin field] -- <command> [args...]
          Ask for Touch ID, then run the command with the item's fields injected; its output is masked.
      wardenrun new <name> [--username U] [--uri URL] [--env VAR] [--length 32] [--charset alnum|full]
          Generate a password, store it in the vault and print only the item's name and id.
      wardenrun setup [--bw PATH]
          Store the vault account (master password typed here, never passed as an argument) and log bw in.
      wardenrun doctor
          Check this installation: signature, hardening, the stored item, bw, Touch ID. Prints no secret.
      wardenrun version | help

    field is password, username, totp, notes, uri, or the name of a custom field.
    """
}
