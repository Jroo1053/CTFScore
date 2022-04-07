*** Settings ***
Library           SeleniumLibrary
Library           XvfbRobot
Library           Screenshot
Library           String
Resource          resource.robot
Suite Setup       Open Browser To Register Page
*** Test Cases ***
Attempt Login
    Go To Login Page
    Input Username    poop
    Input Password    test
    Submit Credentials

Create Account And Login
    ${username}=    Generate Random String
    ${assetone}=    Set Variable    ${VALID ASSET ONE}
    Log To Console    ${VALID_ASSET_ONE}
    ${assettwo}=    Set Variable    ${VALID ASSET TWO}
    Log To Console    ${VALID_ASSET_TWO}
    ${token}=    Register Valid Account    ${username}    ${assetone}    ${assettwo}
    Login Valid Account    ${username}    ${token}

Visit Alert Breakdown Page
    Set Window Size    1500    1500
    Go To Alert Breakdown Page

*** Keywords ***
Register Valid Account
    [Arguments]    ${username}    ${assetone}    ${assettwo}
    Go To Register Page
    Input Register Username    ${username}
    Input Register Asset One    ${assetone}
    Input Register Asset Two    ${assettwo}
    Submit Credentials
    ${token}=    Register Should Have Worked
    [Return]    ${token}

Login Valid Account
    [Arguments]    ${username}    ${password}
    Go To Login Page
    Input Username    ${username}
    Input Password    ${password}
    Submit Credentials
    Index Page Should Be Open

Register Should Have Worked
    Location Should Be    ${REGISTER URL}
    Wait Until Page Contains    ${REGISTER SUCCSSES TEXT}
    ${new_token}=    Get Element Attribute    xpath://code[@id="token_display"]    innerHTML
    Title Should Be    Register | CTFScore
    [Return]    ${new_token}
