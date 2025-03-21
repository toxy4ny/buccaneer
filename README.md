# Buccaneer v.1.0.
This prog parsing JS-file on Server for finds Secrets.

Find All Secrets = {
        'JWT Tokens': [],
        'API Tokens': [],
        'AWS Access Key IDs': [],
        'AWS Secret Access Keys': [],
        'GitHub Tokens': [],
        'GitLab Tokens': [],
        'Slack Webhooks': [],
        'Google API Keys': [],
        'Firebase Secret Keys': [],
        'SSH Private Keys': [],
        'CircleCI Tokens': [],
        'Travis CI Tokens': [],
        'OAuth Access Tokens': [],
        'OAuth Refresh Tokens': []
        
# Good Luck in pentest! Exclusively for educational purposes to find the secrets of crazy programmers in unsafe coding of JS scripts!

# How to run:

python buccaneer.py -u <URL> - single domain.

python buccaneer.py -t domains.txt - multi-parser all url in file.


