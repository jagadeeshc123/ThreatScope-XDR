import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from app.scanner.http_client import SafeHTTPClient

class Crawler:
    def __init__(self, base_url: str, max_pages: int = 25, max_depth: int = 2):
        self.base_url = base_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited = set()
        self.queue = [(base_url, 0)]
        self.pages_content = {} # url -> response text/soup
        self.base_domain = urlparse(base_url).netloc

    def is_same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_domain

    async def crawl(self, http_client: SafeHTTPClient):
        while self.queue and len(self.visited) < self.max_pages:
            current_url, depth = self.queue.pop(0)

            if current_url in self.visited:
                continue
            
            self.visited.add(current_url)

            response, error = await http_client.get(current_url)
            if error or not response:
                continue

            # Check if HTML
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            html_content = response.text
            self.pages_content[current_url] = html_content

            if depth < self.max_depth:
                soup = BeautifulSoup(html_content, "html.parser")
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    full_url = urljoin(current_url, href)
                    
                    # Remove fragment
                    full_url = full_url.split('#')[0]

                    if self.is_same_origin(full_url) and full_url not in self.visited:
                        self.queue.append((full_url, depth + 1))
        
        return self.pages_content
