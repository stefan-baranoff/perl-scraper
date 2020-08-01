# perl-scraper

## Installing
If you're on CentOS 8 ensure the PowerTools repo is enabled: `sudo vim /etc/yum.repos.d/CentOS-PowerTools.repo` and change `enabled=0` to `enabled=1`

```
sudo yum install -y perl-LWP-Protocol-https perl-JSON cpan gcc file-devel
sudo cpan install File::LibMagic
```

The install of `gcc` is for `cpan` which is for installing `File::LibMagic`

If you take out the 'save by file type' stuff you can drop this back to just
`sudo yum install -y perl-LWP-Protocol-https perl-JSON`

## Running
This is pretty self explanatory
`./perl-scraper.pl -u /path/to/file/with/url/list -o /path/to/some/output/directory`

There's usage built in.
