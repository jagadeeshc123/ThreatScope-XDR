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
        self.queue = [(base_url, 0, None)] # (url, depth, parent_url)
        self.pages_content = {} # url -> {'html': text, 'node_info': dict}
        self.base_domain = urlparse(base_url).netloc

    def is_same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_domain

    async def crawl(self, http_client: SafeHTTPClient):
        while self.queue and len(self.visited) < self.max_pages:
            current_url, depth, parent_url = self.queue.pop(0)

            if current_url in self.visited:
                continue
            
            self.visited.add(current_url)

            response, error = await http_client.get(current_url)
            
            status_code = response.status_code if response else None
            content_type = response.headers.get("content-type", "") if response else None

            if error or not response or "text/html" not in content_type:
                # Still record the node if we hit it but it's not HTML
                self.pages_content[current_url] = {
                    'html': None,
                    'node_info': {
                        'url': current_url,
                        'path': urlparse(current_url).path or "/",
                        'status_code': status_code,
                        'content_type': content_type,
                        'page_title': None,
                        'depth': depth,
                        'parent_url': parent_url,
                        'has_forms': False,
                        'has_password_field': False
                    }
                }
                continue

            html_content = response.text
            soup = BeautifulSoup(html_content, "html.parser")
            
            page_title = soup.title.string.strip() if soup.title and soup.title.string else None
            has_forms = len(soup.find_all("form")) > 0
            has_password_field = len(soup.find_all("input", type="password")) > 0

            self.pages_content[current_url] = {
                'html': html_content,
                'node_info': {
                    'url': current_url,
                    'path': urlparse(current_url).path or "/",
                    'status_code': status_code,
                    'content_type': content_type,
                    'page_title': page_title,
                    'depth': depth,
                    'parent_url': parent_url,
                    'has_forms': has_forms,
                    'has_password_field': has_password_field
                }
            }

            if depth < self.max_depth:
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    full_url = urljoin(current_url, href)
                    
                    # Remove fragment
                    full_url = full_url.split('#')[0]

                    if self.is_same_origin(full_url) and full_url not in self.visited:
                        self.queue.append((full_url, depth + 1, current_url))
        
        return self.pages_content
