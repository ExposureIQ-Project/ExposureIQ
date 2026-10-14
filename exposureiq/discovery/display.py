def print_ports(ports: list[dict]) -> None:
    """Display discovered open ports in a readable table."""
    if not ports:
        print("\nNo open ports found.")
        return

    port_width = max(
        len("PORT"),
        max(len(str(item["port"])) for item in ports),
    )
    protocol_width = max(
        len("PROTOCOL"),
        max(len(item["protocol"]) for item in ports),
    )
    service_width = max(
        len("SERVICE"),
        max(len(item["service"]) for item in ports),
    )

    separator = (
        f"+{'-' * (port_width + 2)}"
        f"+{'-' * (protocol_width + 2)}"
        f"+{'-' * (service_width + 2)}+"
    )

    print("\nOpen TCP Ports")
    print(separator)
    print(
        f"| {'PORT':<{port_width}} "
        f"| {'PROTOCOL':<{protocol_width}} "
        f"| {'SERVICE':<{service_width}} |"
    )
    print(separator)

    for item in ports:
        print(
            f"| {item['port']:<{port_width}} "
            f"| {item['protocol']:<{protocol_width}} "
            f"| {item['service']:<{service_width}} |"
        )

    print(separator)
    print(f"Total open ports: {len(ports)}")
