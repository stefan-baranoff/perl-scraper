# perl-scraper
# If you're on CentOS 8 ensure the PowerTools repo is enabled:
#  sudo vim /etc/yum.repos.d/CentOS-PowerTools.repo
#  Change `enabled=0` to `enabled=1`
# The install of `gcc` is for cpan which is for LibMagic

# If you take out the 'save by file type' stuff you can drop this back to just
# sudo yum install -y perl-LWP-Protocol-https perl-JSON
sudo yum install -y perl-LWP-Protocol-https perl-JSON cpan gcc file-devel
sudo cpan install File::LibMagic
