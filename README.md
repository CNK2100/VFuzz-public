# VFuzz-public

>Summary

VFuzz is a fuzzing approach for finding vulnerabilities in the Z-Wave smart home devices. VFuzz found flaws in  major Z-Wave chipsets series. These vulnerabilities allow an attacker to inject malicious Z-Wave packets that can control, impersonate, or cause a denial-of-service (DoS) on vulnerable devices. DoS on controller disables intrusion and events notification to the remote house owner resulting in illegal house access without security systems being activated.

>Conference paper

VFuzz details, implementations, and experimental results are available in our paper published in IEEE Access Journal at https://ieeexplore.ieee.org/document/9663293.

C. K. Nkuba, S. Kim, S. Dietrich and H. Lee, "Riding the IoT Wave With VFuzz: Discovering Security Flaws in Smart Homes," in IEEE Access, vol. 10, pp. 1775-1789, 2022, doi: 10.1109/ACCESS.2021.3138768.

>Demo video of vulnerability impact

We provide a demo video highlighting found vulnerabilities’ impact on smart home devices at https://www.youtube.com/watch?v=RdVWxwg3FIE&ab_channel=C.

>Responsible disclosure

We filed several vulnerability reports to the US CERT/CC division in order to work with the  respective chipsets and device manufacturers to fix and mitigate the threats that we discovered. 

Below are the CVE references:
1. https://kb.cert.org/vuls/id/142629
2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9057
3. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9058
4. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9059
5. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9060
6. https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10137


>How to stop the attacks?

Z-Wave devices with 100, 200, 300 series chipsets are one-time-programmable and cannot be updated to fix the vulnerabilities. For the above-listed devices, we are planning to develop an intrusion detection system to mitigate these external attacks.

For devices with 500 and 700 chipset series, the above-mentioned vulnerabilities can be mitigated through firmware update.

We also advise house owners to have a diversified set of smart home devices with different technologies such as Z-Wave, ZigBee, Thread, etc.  so that when the former is attacked, the latter can capture the intrusion, activate security systems, and notify the remote user via mobile app.


>Ethical considerations

The  VFuzz  public version WILL provide source code for core Z-Wave fuzzing functionalities while reducing advanced features that could be misused by bad actors to attack smart home devices. For the same ethical considerations, we are not releasing the VFuzz PoC exploit code 

>About

This repository is maintained by Carlos Nkuba. For reporting bugs, you can submit an issue to the GitHub repository.
