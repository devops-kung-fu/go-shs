# Security Health Score (SHS)

__NOTICE: This documentation is under massive development. Consider this volatile__

## Overview

The Security Health Score (SHS) is a number calculated with CVSS vectors representing application, hardware, or network vulnerabilities. 

## Why create another score? 
(Quick Thoughts)
* We need a way to calculate security health beyond just the application stack
* CVSS Severity isn't enough.
* Lows and mediums are often ignored in calculations such as defect density even though they pose a risk

## Uses
(Quick Thoughts)
* Calculate the security health of an open source component
* Calculate the security health of a single repository
* Calculate the security health of a group of repositories 
* Calculate the security health of a system in production (application code, infrastructure vulnerabilities, etc)
* Roll up all vulnerabilities to one number that represents the Security Health of an entire organization

## Must haves
* Output a "credit score" - a single number in the range of 0-1000. Easy to understand
* Lows, Mediums, Highs, and Critical vulnerabilities need to be weighted

## Credits

CVSS is used with permission from FIRST.org. More information can be found at [https://www.first.org/cvss/](https://www.first.org/cvss/)