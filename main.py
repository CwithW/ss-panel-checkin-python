import argparse
import logging
import urllib3
import os
from checkin import Checkin

class CheckinFailedException(Exception):
    """Custom exception for checkin failures."""
    pass

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = argparse.ArgumentParser(description="SS-Panel Checkin Script")
    parser.add_argument("--host", required=True, help="website host")
    parser.add_argument("--email", required=True, help="user email")
    parser.add_argument("--passwd", required=True, help="user password")
    parser.add_argument("--save-session", action='store_true', help="save session to file",default=True)
    parser.add_argument("--insecure", action='store_true', help="allow insecure SSL connections", default=False)
    args = parser.parse_args()

    if args.save_session and not os.path.exists("./session"):
        os.makedirs("./session")

    try:
        c = Checkin(args.host, args.email, args.passwd, args.insecure)
        if args.save_session:
            c.load_session()
        if not c.handle():
            raise CheckinFailedException("Checkin failed")
        if args.save_session:
            c.save_session()
    except Exception as e:
        logging.error(e)
        if not isinstance(e, CheckinFailedException):
            raise

if __name__ == "__main__":
    main()