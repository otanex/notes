## Testing GitHub Pages

# Decode the secret

### Decode the following secret. The flag is in a GUID form.

```
ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrcHZhRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeU5EVXNJbUYxWkNJNklrTlVSaUlzSWtkVlNVUWlPaUl5WTJJNFltVmtPUzFqT0RkbExUUTBNekV0T1RVM09DMDVZekV4Tm1Ka056a3hNMk1pTENKSVlYTk5Sa0VpT2lKTllYbGlaVDhpZlEuNTh2c0dMTTJXRU5hbEUtVF9WVmI0b0xmcXlhaFAyWFFiRmYxX2hlUUxJcw==
```

go to cyberchef and decode it (from base64)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyNDUsImF1ZCI6IkNURiIsIkdVSUQiOiIyY2I4YmVkOS1jODdlLTQ0MzEtOTU3OC05YzExNmJkNzkxM2MiLCJIYXNNRkEiOiJNYXliZT8ifQ.58vsGLM2WENalE-T_VVb4oLfqyahP2XQbFf1_heQLIs
```

go to jwt.io [https://jwt.io/] to decode the above 

decoded payload data

```
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 151623902245,
  "aud": "CTF",
  "GUID": "2cb8bed9-c87e-4431-9578-9c116bd7913c",
  "HasMFA": "Maybe?"
}
```


OR you can click this link for cyberChef decode

`
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)JWT_Decode()&input=WlhsS2FHSkhZMmxQYVVwSlZYcEpNVTVwU1hOSmJsSTFZME5KTmtscmNGaFdRMG81TG1WNVNucGtWMGxwVDJsSmVFMXFUVEJPVkZrelQwUnJkMGxwZDJsaWJVWjBXbE5KTmtscmNIWmhSelJuVWtjNWJFbHBkMmxoVjBZd1NXcHZlRTVVUlRKTmFrMDFUVVJKZVU1RVZYTkpiVVl4V2tOSk5rbHJUbFZTYVVselNXdGtWbE5WVVdsUGFVbDVXVEpKTkZsdFZtdFBVekZxVDBSa2JFeFVVVEJOZWtWMFQxUlZNMDlETURWWmVrVjRUbTFLYTA1NmEzaE5NazFwVEVOS1NWbFlUazVTYTBWcFQybEtUbGxZYkdsYVZEaHBabEV1TlRoMmMwZE1UVEpYUlU1aGJFVXRWRjlXVm1JMGIweG1jWGxoYUZBeVdGRmlSbVl4WDJobFVVeEpjdz09
`

#### answer : 2cb8bed9-c87e-4431-9578-9c116bd7913c
