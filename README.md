# cha-MissingPatchAuditor
Compares the installed software versions against a known vulnerabilities database (e.g., retrieved from NIST) and reports on missing security patches. - Focused on Assists with the automation of configuration hardening based on security best practices. Allows users to define configuration baselines in YAML or JSON format and automatically check system configurations against these baselines, highlighting deviations and suggesting corrective actions.

## Install
`git clone https://github.com/ShadowStrikeHQ/cha-missingpatchauditor`

## Usage
`./cha-missingpatchauditor [params]`

## Parameters
- `-h`: Show help message and exit
- `-b`: Path to the baseline YAML or JSON file.
- `-d`: Path to the vulnerabilities database JSON file.
- `-o`: No description provided

## License
Copyright (c) ShadowStrikeHQ
