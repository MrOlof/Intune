# Intune  Repository

Welcome to my Intune PowerShell repository! Here you will find a collection of PowerShell scripts designed to manage and automate various tasks in Microsoft Intune. Feel free to explore, use, and modify the scripts to suit your needs.

## Table of Contents

- [Introduction](#introduction)
- [Usage Instructions](#usage-instructions)
- [Contributing](#contributing)
- [License](#license)

## Introduction

This repository contains a variety of PowerShell scripts designed to simplify and automate the management of Microsoft Intune environments. From device management to policy configuration, these scripts aim to streamline your Intune administration tasks.

## Usage Instructions

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/MrOlof/Intune.git
    ```

2. **Install the Microsoft.Graph.Intune Module**:
    Ensure you have the required module installed:
    ```powershell
    Install-Module -Name Microsoft.Graph.Intune
    ```

3. **Run a Script**:
    Open a PowerShell terminal and navigate to the directory of the script you want to run. Execute the script with the appropriate parameters, for example:
    ```powershell
    .\Get-IntuneManagedDevices.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-client-secret"
    ```

## Contributing

Contributions are welcome! If you have a script that you think would be useful to others, please submit a pull request. Ensure that your script is well-documented and follows the existing code style.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/YourFeature`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

