#!/bin/bash

#
# https://github.com/Massl123/check_apache_ssl_certs
#

set -uo pipefail

certWarnings=()
outputLines=()


# Check server certificates
certFiles=$(grep -E '^\s*SSLCertificateFile\s.+$' -h /etc/httpd/conf.d/*.conf | sed 's/\s*$//g' | sed 's/^\s*//g' | cut '-d ' -f2- | sort | uniq)
okDateUnix=$(date -d "+30 days" +%s)
currentDateUnix=$(date +%s)


outputLines+=( "◼◼◼◼◼ Server certificates ◼◼◼◼◼\n" )
for cert in ${certFiles[@]}
do
    certLines=()
    certLines+=( "◼◼◼◼▶ ${cert}\n" )
    CN=$(openssl x509 -noout -subject -in ${cert} | grep -oE "CN.*?=.*" | cut -d= -f2)
    certLines+=( "CN: ${CN}\n" )
    expireDate="$(openssl x509 -enddate -noout -in ${cert} | cut -d= -f2)"
    expireDateUnix=$(date -d "${expireDate}" +%s)
    #echo -n $(date -d @${expireDateUnix} -I)
    certLines+=( "Expires on: ${expireDate}\n" )
    certLines+=( "Found in configuration files:\n" )
    for conf in $(grep "^ *SSLCertificateFile.*${cert}" -H /etc/httpd/conf.d/*.conf | cut "-d:" -f1)
    do
        certLines+=( "$conf\n" )
    done
    certLines+=( "\n" )
    if [ $expireDateUnix -le $okDateUnix ]
    then
        daysUntil="$(( $((${expireDateUnix} - ${currentDateUnix})) / 60 / 60 / 24))"
        certWarnings+=( "\"${CN} (${daysUntil}d)\"" )
        outputLines+=( "${certLines[@]}" )
    fi
done

# Check intermediate certificates
certCAFiles=$(grep -E '^\s*SSLCACertificateFile\s.+$' -h /etc/httpd/conf.d/*.conf | sed 's/\s*$//g' | sed 's/^\s*//g' | cut '-d ' -f2- | sort | uniq)

outputLines+=( "◼◼◼◼◼ CA certificates ◼◼◼◼◼\n" )
for cert in ${certCAFiles[@]}
do
    # Snippet for parsing PEM file from https://serverfault.com/a/718751
    txt=""
    while read line
    do
        if [ "${line//END}" != "$line" ]; then
            # Cert complete, start tests
            txt="$txt$line\n"
            certificate="$txt"
            txt=""

            certLines=()
            certLines+=( "◼◼◼◼▶ ${cert}\n" )
            CN=$(echo -e "${certificate}" | openssl x509 -noout -subject | grep -oE "CN.*?=.*" | cut -d= -f2)
            certLines+=( "CN: ${CN}\n" )
            expireDate="$(echo -e "${certificate}" | openssl x509 -enddate -noout | cut -d= -f2)"
            expireDateUnix=$(date -d "${expireDate}" +%s)
            #echo -n $(date -d @${expireDateUnix} -I)
            certLines+=( "Expires on: ${expireDate}\n" )
            certLines+=( "Found in configuration files:\n" )
            for conf in $(grep "^ *SSLCACertificateFile.*${cert}" -H /etc/httpd/conf.d/*.conf | cut "-d:" -f1)
            do
                certLines+=( "$conf\n" )
            done
            certLines+=( "\n" )
            if [ $expireDateUnix -le $okDateUnix ]
            then
                daysUntil="$(( $((${expireDateUnix} - ${currentDateUnix})) / 60 / 60 / 24))"
                certWarnings+=( "\"${CN} (${daysUntil}d)\"" )
                outputLines+=( "${certLines[@]}" )
            fi
        else
            txt="$txt$line\n"
        fi
    done < $cert
done

if [ ${#certWarnings[@]} -gt 0 ]
then
    echo "WARNING - Expiring certs: ${certWarnings[@]} - check output for more info"
    echo -e " ${outputLines[@]}"
    exit 1
fi

echo "Ok: All certs are valid for at least 30 days"
exit 0
