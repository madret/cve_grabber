# vuln_checker
Checks for vulnerabilites in software/hardware + version and thereafter grabs corresponding CVE information. 
Useful for security advisories.

## ** Warning **
NVD recently posted the following notice about temporary API restrictions that will affect the script:
![image](https://github.com/madret/vuln_checker/assets/56820649/8fe12454-8ec4-4d7c-97a6-4cb75585deb7)

## Example usage
1. Run the script `.\vuln_checker.ps1 -ExecutionPolicy Bypass`
2. **New**: The script now gives two options, 1: Perform vulnerability search followed by CVE search, 2: Search per CVE ID right away.
4. Enter name of software/hardware + version;
5. Wait for first output;
6. Thereafter enter desired CVE ID(s);
7. After second output, grab actionable CVE information:

![image](https://github.com/madret/vuln_checker/assets/56820649/393765c0-5e06-40e6-be0a-1e7c69b57d40)

********************************************************************************************************
![image](https://github.com/madret/vuln_checker/assets/56820649/15d47021-3c23-4f68-bcb5-705ff0e93c29)

### No additional powershell modules need to be installed.

vuln_checker is maintained by [@b41ss](https://twitter.com/b41ss) 
