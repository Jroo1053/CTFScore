*** Settings ***
Documentation     resrource file for UI test cases
Library           SeleniumLibrary

*** Variables ***

${SERVER}               localhost
${BROWSER}              firefox
${DELAY}                0
${LOGIN URL}            http://${SERVER}:5000/login
${INDEX URL}            http://${SERVER}:5000/index
${REGISTER URL}         http://${SERVER}:5000/register
${LOGOUT URL}           http://${SERVER}:5000/logout
${BREAKDOWN URL}        http://${SERVER}:5000/alerts
${VALID USER}           ron_obvious
${VALID PASSWORD}     
${VALID ASSET ONE}      192.168.56.1
${VALID ASSET TWO}     192.168.56.101
${REGISTER SUCCSSES TEXT}     Note: This token will only be shown once
*** Keywords ***

Open Browser To Login Page
    Open Browser    ${LOGIN URL}    ${BROWSER}  
    Maximize Browser Window
    Set Selenium Speed    ${DELAY}
    Login Page Should Be Open


Open Browser To Register Page
    Open Browser    ${REGISTER URL}    ${BROWSER}
    Maximize Browser Window
    Set Selenium Speed    ${DELAY}
    Register Page Should Be Open

Login Page Should Be Open
    Title Should Be  Login | CTFScore

Register Page Should Be Open
    Title Should Be  Register | CTFScore


Go To Login Page
    Go To    ${LOGIN URL}
    Login Page Should Be Open


Go To Logout Page
    Go To  ${LOGOUT URL}

Go To Index Page
    Go To  ${INDEX URL}
    Index Page Should Be Open

Go To Register Page
    Go To   ${REGISTER URL}
    Register Page Should Be Open

Go To Alert Breakdown Page
    Go To     ${BREAKDOWN URL}
    Breakdown Page Should Be Open
Input Username
    [Arguments]    ${username}
    Input Text    username    ${username}

Input Password
    [Arguments]    ${password}
    Input Text    access_token    ${password}

Input Register Username
    [Arguments]     ${username}
    Input Text      username    ${username}

Input Register Asset One
    [Arguments]     ${assetone}
    Input Text      registered_assets-0    ${assetone}

Input Register Asset Two
    [Arguments]     ${assettwo}
    Input Text      registered_assets-1     ${assettwo}

Submit Credentials
    Click Button    submit

Index Page Should Be Open
    Location Should Be    ${INDEX URL}
    Title Should Be    Home | CTFScore

Breakdown Page Should Be Open
    Location Should Be    ${BREAKDOWN URL}