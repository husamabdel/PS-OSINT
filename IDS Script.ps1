﻿
###################################################################
#    IDS_SCRIPT_V3
#    @Author: Husam Abdalla
#
#	HOW TO CONVERT JSON:	
#	$obj = Invoke-WebRequest -uri "<API-URI>"	
#	$obj2 = ConvertFrom-JSON -InputObject $obj 
#
#   Date Created: 7/3/2022
#   Last Modified: $NULL
#
#   Hetrix API:
#   
#   https://api.hetrixtools.com/v2/<API_TOKEN>/blacklist-check/ipv4/<IP_ADDRESS>/
#
#   VirusTotal API:
#   
#   curl --request GET \
#   --url https://www.virustotal.com/api/v3/ip_addresses/{ip} \
#   --header 'x-apikey: <your API key>'
#
#
#   apivoid: 
#
###################################################################

#Globals::

$Global:ipToScan
$Global:htrx
$Global:geo
$Global:vtot
$Global:apiKey
$Global:apiKey2
$outPath = "${env:USERPROFILE}\Documents\report.txt"

#HetrixTools Function

function getHetrix($ip){

    $ip = $ipToScan

    $obj = Invoke-WebRequest -Uri "https://api.hetrixtools.com/v2/${apiKey}/blacklist-check/ipv4/${ip}/"
    $hetrix = ConvertFrom-Json -InputObject $obj

    return $hetrix

}

#IPAPI Function

function getGeo($ip){

    $ip = $ipToScan

    $obj = Invoke-WebRequest -Uri "https://ipapi.co/${ipToScan}/json/"
    $geoo = ConvertFrom-Json -InputObject $obj

    return $geoo

}

#VirusTotal Function

function getVtotal($ip){

    $ip = $ipToScan

    $obj = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/ip_addresses/${ipToScan}" -Method GET -Headers @{'x-apikey'= $apiKey2}
    $vtotoal = ConvertFrom-Json -InputObject $obj

    return $vtotoal

}

#Simple function to advise users about the IP address reputation

function verdict(){

    $VThits = 0
    $HEThits= 0

    if($vtotoal.data.attributes.last_analysis_stats.malicious -gt 0){
    
        $VThits++

        } if($htrx.blacklisted_count -gt 0){
    
            $HEThits++

            } if($vtotoal.data.attributes.last_analysis_stats.malicious -gt 0 -and $htrx.blacklisted_count -gt 0){
        
                Write-Output "Verdict: BLOCK `n Reason: IP was confirmed to be blacklisted using multiple API's to OSINT tool."
                return

                } if($vtotoal.data.attributes.last_analysis_stats.malicious -gt 0 -or $htrx.blacklisted_count -gt 0){
                
                    Write-Output "Verdict: BLOCK `nReason: IP was confirmed to be blacklisted using at least one OSINT API provider."
                    return

                    }
    Write-Output "Insufficient evidence to give a verdict of block, However, proceed with BLOCK if there is ANY reasonable doubt that this IP was observed sending malicious traffic"
    




}



#Main:


function main(){

    Write-Output '======================= IDS_SCRIPT_V3 @Author: Husam Abdalla ======================='


    if($(Test-Path -Path $outPath) -eq $false){
    
        New-Item -Path $outPath
    
        } else{
    
            Remove-Item $outPath -Force

            }

    
    $ipToScan = Read-Host 'Please type the IP address to scan'
    $apiKey = Read-Host 'Please enter the Hetrix Tools API Key'
    $apiKey2 = Read-Host 'Please enter the VirusTotal API Key'

    $htrx = getHetrix($ipToScan)
    $geo = getGeo($ipToScan)
    $vtot = getVtotal($ipToScan)


    Write-Output 'Hetrix Tools Report:' | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output '====================' | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output "Black List count:" $htrx.blacklisted_count | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output "Black Listed on:" $htrx.blacklisted_on | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output "Report Links:" $htrx.links | Tee-Object -Append $outPath -Encoding 'UTF-8'
    
    #Hetrix Tools Report completed
    
    echo "" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    echo "" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    echo "====================" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output 'IP Geolocation (IP API):' | Tee-Object -Append $outPath -Encoding 'UTF-8'
    echo "====================" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output $geo | Tee-Object -Append $outPath -Encoding 'UTF-8'

    #IP geolocation report completed.

    echo "" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    echo "" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    echo "====================" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output 'VirusTotal Report:' | Tee-Object -Append $outPath -Encoding 'UTF-8'
    echo "====================" | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output $vtot.data.attributes.last_analysis_stats | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Write-Output "`n"$vtot.data.attributes.last_analysis_results | Tee-Object -Append $outPath -Encoding 'UTF-8'
    #VirusTotal report complete.

    verdict | Tee-Object -Append $outPath -Encoding 'UTF-8'
    Get-Content -Path $outPath

}

main
