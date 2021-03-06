# dns-reroute
Small DNS server in Perl designed to inject fake DNS entries.

# Purpose
This small script was created to make it easy to make 'fake' DNS entries that do not exist within an actual nameserver
anywhere. Just configure this script, run it, then point the DNS of whatever you want ( your own machine, coworkers
machines, etc ) to the IP address of your box. Once you do this, everyone with their DNS changed will see the new
'fake' DNS entries you configured.

Fun bonus feature of the script is that it creates a log seeing everything queried through it. Want to see all the
various nonsense domains that are looked up constantly by Windows? Run this script and find out.

# Usage
* Clone this repo
* Install the libidn-devel package needed by Net::DNS
  ```sh
  sudo zypper in libidn-devel ( on OpenSUSE )
  ```
* Install the dependent CPAN modules Net::DNS and Net::DNS::Nameserver. These will both be installed if you install Net::DNS through CPAN.
  ```sh
  sudo cpan install Net::DNS
  ```
* Replace 'COMPANYDOMAIN.com' in reroute.pl with the a domain you wish to redirect entries within.
* Alter example conf.xml as desired to redirect various things
* Run the script as root ( root is required to bind to the default DNS port )
  ```sh
  sudo ./reroute.pl
  ```
