*** Settings ***
Library           SeleniumLibrary
Library           XvfbRobot
Library           Screenshot
Library           String
Resource          resource.robot

*** Test Cases ***
Attempt Login
    [Documentation]    To open GUI and login with invalid credentials
    ${chrome options} =     Evaluate    sys.modules['selenium.webdriver'].ChromeOptions()    sys, selenium.webdriver
    Call Method    ${chrome options}   add_argument    headless
    Call Method    ${chrome options}   add_argument    disable-gpu
    Create Webdriver    Chrome    chrome_options=${chrome options}
    Set Window Size    1500    1500
    Go To Login Page
    Set Browser Implicit Wait    5
    Input Username    poop
    Input Password    test
    Submit Credentials

Create Account And Login
    Start Virtual Display    1920    1080
    ${chrome options} =    Evaluate    sys.modules['selenium.webdriver'].ChromeOptions()    sys, selenium.webdriver
    Call Method    ${chrome options}    add_argument    headless
    Call Method    ${chrome options}    add_argument    disable-gpu
    Call Method    ${chrome options}    add_argument    no-sandbox
    Create Webdriver    Chrome    chrome_options=${chrome options}
    Open Browser To Register Page
    Set Browser Implicit Wait    5
    Set Window Size    1500    1500
    ${username}=    Generate Random String
    ${assetone}=    Set Variable    ${VALID ASSET ONE}
    Log To Console    ${VALID_ASSET_ONE}
    ${assettwo}=    Set Variable    ${VALID ASSET TWO}
    Log To Console    ${VALID_ASSET_TWO}
    ${token}=    Register Valid Account    ${username}    ${assetone}    ${assettwo}
    Login Valid Account    ${username}    ${token}

Visit Alert Breakdown Page
    Start Virtual Display    1920    1080
    ${chrome options} =    Evaluate    sys.modules['selenium.webdriver'].ChromeOptions()    sys, selenium.webdriver
    Call Method    ${chrome options}    add_argument    headless
    Call Method    ${chrome options}    add_argument    disable-gpu
    Call Method    ${chrome options}    add_argument    no-sandbox
    Create Webdriver    Chrome    chrome_options=${chrome options}
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
