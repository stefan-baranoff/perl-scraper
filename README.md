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

# tc_portal_enrichment

## Installing
On top of what perl-scraper already provides, on a CentOS system you should only need to add:
```
sudo yum install -y perl-DBD-SQLite.x86_64
```

## Running
This is pretty self explanatory, too. Date/time formats are the strftime equivalent of `%FT%T%:z` which expands to `%Y-%m-%dT%H:%M:S%:z` which as an example looks like `2020-08-13T08:15:35+00:00`. The `+00:00` for those unfamiliar is a timezone offset with 00:00 being UTC/Zulu time and EST=`-05:00`/EDT=`-04:00`.

On environment variable, `TC_API_KEY`, needs to be set. You can generate an API key via the Trinity Cyber client portal UI or GraphQL API.

Actual run line, assuming your Trinity Cyber portal API key is stored in `~/.tc_api_key`:
`TC_API_KEY=`cat ~/.tc_api_key` ./tc_portal_enrichment -a <start date> -b <end date> -d /path/to/some/output/directory/from/scraper/run`
