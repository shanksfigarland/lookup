document.getElementById('lookup-btn').addEventListener('click', () => {
  const input = document.getElementById('input').value.trim();
  const lookupType = document.getElementById('lookup-type').value;
  const resultsDiv = document.getElementById('results');

  if (!input) {
    resultsDiv.innerHTML = '<p>Please enter a valid input.</p>';
    return;
  }

  // Clear previous results
  resultsDiv.innerHTML = '';

  // Define lookup URLs
  const lookupUrls = {
    "ip-abuse": [
      "https://www.virustotal.com/gui/search/",
      "https://www.abuseipdb.com/check/",
      "https://viz.greynoise.io/ip/",
      "https://exchange.xforce.ibmcloud.com/ip/",
      "https://www.talosintelligence.com/reputation_center/lookup?search=",
      "https://www.shodan.io/host/",
      "https://www.projecthoneypot.org/ip_",
      "https://feodotracker.abuse.ch/browse/host/"
    ],
    "ip-info": [
      "https://www.whois.com/whois/",
      "https://whois.domaintools.com/"
    ],
    "hash-rep": [
      "https://www.virustotal.com/gui/search/",
      "https://exchange.xforce.ibmcloud.com/malware/",
      "https://www.talosintelligence.com/talos_file_reputation?s=",
      "https://bazaar.abuse.ch/browse.php?search=sha256:"
    ],
    "domain-rep": [
      "https://otx.alienvault.com/indicator/domain/",
      "https://www.virustotal.com/gui/search/",
      "https://www.barracudacentral.org/lookups/lookup-reputation?lookup_entry=",
      "https://urlhaus.abuse.ch/browse.php?search="
    ],
    "crypto-info": [
      "https://www.blockchain.com/explorer/search?search="
    ],
    "lolbin-lookup": [
      "https://lolbas-project.github.io/#"
    ],
    "winbindex-lookup": [
      "https://winbindex.m417z.com/?file="
    ],
    "cc-magic": [
      "https://cyberchef.org/#recipe=Magic(3,false,false,'')&input="
    ],
    "cc-defang": [
      "https://cyberchef.org/#recipe=Defang_URL(true,true,true,'Valid%20domains%20and%20full%20URLs')Defang_IP_Addresses()URL_Decode()&input="
    ],
    "cc-resolve-domain": [
      "https://gchq.github.io/CyberChef/#recipe=Find_/_Replace(%7B'option':'Simple%20string','string':'%2520'%7D,'%5C%5Cn',true,false,true,false)Fork('%5C%5Cn','%5C%5Cn',false)DNS_over_HTTPS('https://dns.google.com/resolve','A',false,false)JPath_expression('Answer%5B0%5D%5B%5C'name,data%5C'%5D','',true)Find_/_Replace(%7B'option':'Simple%20string','string':'.%22%22'%7D,'%20%3D%3E%20',true,false,true,false)Find_/_Replace(%7B'option':'Simple%20string','string':'%22'%7D,'',true,false,true,false)&input="
    ],
    "cve-info": [
      "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="
    ],
    "fileext-info": [
      "https://fileinfo.com/extension/"
    ],
    "file-info": [
      "https://www.file.net/search.html?q=site:file.net+"
    ],
    "mac-info": [
      "https://maclookup.app/search/result?mac="
    ],
    "ua-info": [
      "https://Henard.tech/ua-parser.html?ua="
    ],
    "error-info": [
      "https://login.microsoftonline.com/error?code="
    ],
    "event-info": [
      "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid="
    ],
    "vpn-info": [
      "https://iphub.info/?ip=",
      "https://www.ip2location.com/demo/",
      "https://db-ip.com/",
      "https://metrics.torproject.org/rs.html#search/"
    ],
    "email-info": [
      "https://exchange.xforce.ibmcloud.com/url/",
      "https://mxtoolbox.com/SuperTool.aspx?run=toolpage&action=blacklist:"
    ]
  };

  // Open relevant tabs for the selected lookup type
  if (lookupUrls[lookupType]) {
    lookupUrls[lookupType].forEach(url => {
      chrome.tabs.create({ url: url + encodeURIComponent(input) });
    });
  } else {
    resultsDiv.innerHTML = '<p>Unsupported lookup type.</p>';
  }
});