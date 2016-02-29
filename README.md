# SSLFingerPrint
When using open Wifis, like the ones at coffe shops, airports and outlet malls, you can't be sure that your traffic is safe. 

Even when it's HTTPS. This small script uses a remote server to double check the connection.

### Issues:

False positives. If a domain, like Google.com is wildly distributed and might use many different SSL certificates. That means, the check done by the remote server might get a differnt certificate than the one done by your local machine. One way to fix this, is to ensure that your server is regionally close to you as most of these changes are geographically applied. 
## Install

1. Place `check.py` in your `$PATH`.
2. Create an alias for it in your `.bashrc` or `.bash_profile`
    - `alias sslcheck='python check.py '`

## Run

` sslcheck google.com`

```
Checking: google.com
Local: SHA1 Fingerprint=16:ED:EA:ED:B6:02:2B:50:44:42:EE:FB:AF:B2:F6:6A:4D:CF:DD:C6
Remote: SHA1 Fingerprint=16:ED:EA:ED:B6:02:2B:50:44:42:EE:FB:AF:B2:F6:6A:4D:CF:DD:C6
Finger print matched. This means you're safe
```

# Shell based check

If you want to do it the old way, you can use the following two files placed under shell

Place the two files in your path.

How to run:
	
	sslRun.sh example.com -sha1
	
OR

	sslRun.sh example.com -md5

Configure:

In the sslRun.sh modify the `YOURSERVER` to your ssh login for any *nix based server with ssh access. 

eg
	
	admin@example.com
	
	
Install in your $PATH.

Mine is located at bin and looks likes
<pre>
.	
├── [
├── bash
├── cat
├── chmod
├── ssl.sh
├── sslRun.sh
|__....
</pre>

Note:

	Remove the file extension for easier access.
	
Example Output:
<pre>
data:~ joubin$ sslRun google.com -sha1
Remote: SHA1 Fingerprint=6A:A6:C5:AA:42:4E:69:F4:34:71:1F:02:C5:DD:A2:05:3F:06:2B:60
Local: SHA1 Fingerprint=6A:A6:C5:AA:42:4E:69:F4:34:71:1F:02:C5:DD:A2:05:3F:06:2B:60
</pre>


Why:

<blockquote>
The Internet is a cooperative PUBLIC DATA NETWORK. Its data traffic flows around the globe freely, transported by an incredible variety of intermediate carriers. These carriers cooperate because they need each other equally: “I'll carry your traffic if you'll carry mine.” And the system works. But with all of this traffic zipping around all over the place, in full public view, how do we KNOW that we are really connected to our bank, our medical records database, or any other public or private website? Websites are (obviously) easy to create, so copying a popular website and redirecting traffic there would not be difficult. And, unfortunately, the world has no shortage of people who would like to do that.
The original un-secured HTTP web connections never attempted to authenticate or encrypt their connections. Users who knew enough to wonder and worry could only hope that they were actually interacting with the website they intended. And that was fine back when the Internet was just a curiosity. But the Internet has grown into a resource where people conduct business, place orders, exchange stock, refer to their medical histories, perform their banking, and everything else—very much as they do in the physical world. For the “cyber versions” of these activities to be feasible, users expect, need, and must have security and privacy.
</blockquote>
~ grc.com