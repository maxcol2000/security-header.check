import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque

visited_urls = set()

def test_security_headers(url):
    try:
        response = requests.get(url)
        security_headers = response.headers

        x_frame_options = 'X-Frame-Options' in security_headers
        content_security_policy = 'Content-Security-Policy' in security_headers
        x_content_type_options = 'X-Content-Type-Options' in security_headers
        x_xss_protection = 'X-XSS-Protection' in security_headers

        print(f"X-Frame-Options {'found' if x_frame_options else 'not found'}")
        print(f"Content-Security-Policy {'found' if content_security_policy else 'not found'}")
        print(f"X-Content-Type-Options {'found' if x_content_type_options else 'not found'}")
        print(f"X-XSS-Protection {'found' if x_xss_protection else 'not found'}")

    except requests.RequestException as e:
        print(f"Error fetching URL: {url}, {e}")

def extract_internal_urls(url, base_url):
    internal_urls = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href.startswith('http'):
                parsed_href = urlparse(href)
                if parsed_href.netloc == urlparse(base_url).netloc:
                    internal_urls.append(href)
            else:
                internal_url = urljoin(base_url, href)
                internal_urls.append(internal_url)

    except requests.RequestException as e:
        print(f"Error fetching URL: {url}, {e}")

    return internal_urls

def crawl_and_test_vulnerabilities(start_url):
    queue = deque([start_url])

    while queue:
        url = queue.popleft()

        if url in visited_urls:
            continue

        visited_urls.add(url)

        test_security_headers(url)

        internal_urls = extract_internal_urls(url, start_url)
        for internal_url in internal_urls:
            if internal_url not in visited_urls:
                queue.append(internal_url)

website_url = '--url--'
crawl_and_test_vulnerabilities(website_url)