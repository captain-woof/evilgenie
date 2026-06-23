import browser as b
import argparse
import traceback
from urllib.parse import urlparse
from threading import Event    

# MAIN
if __name__ == "__main__":
    # ARGPARSE TODO
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", action="store", required=True, help="URL of the login page of the website; format: 'https://site.com'")

    args = parser.parse_args()
    urlLoginPage = args.url

    # Create browser
    print(f"[.] Creating browser")
    contextManager, playwright, browser, context = b.createBrowser(
        downloadsPath="/home/kali/projects/optiv-redteam/evilgenie/testdir"
        )
    if browser is None:
        raise Exception("Browser object is None")
    page = browser.new_page()

    # Create store
    urlsVisited = set()
    domainsVisited = set()

    # Start capture
    try:
        print(f"[.] Starting capture...\nPress Ctrl + C to stop capturing")

        # Event listener - capture all URLs
        page.on("request", lambda r: urlsVisited.add(r.url))        

        # Open target page
        page.goto(
            url=urlLoginPage,
            timeout=0.0
        )

        # Allow user to perform interactions; keep browser open 
        Event().wait()

        # Capture fields

        # Capture POST requests

        # Capture cookies

    # End capture on Ctrl + C
    except KeyboardInterrupt:
        print(f"[.] Ending capture...")

    # For any other exceptions
    except Exception as e:
        traceback.print_exception(e)

    # Create phishlet with all gathered information
    finally:
        for url in urlsVisited:
            urlParsed = urlparse(url=url)

            domainsVisited.add(urlParsed.hostname)

        print(domainsVisited)
    