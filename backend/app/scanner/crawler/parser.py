from typing import List, Optional, Set, Dict, Any
from bs4 import BeautifulSoup
from backend.app.scanner.crawler.normalizer import URLNormalizer
from shared.schemas.discovery import FormMetadataSchema, FormFieldSchema


class HTMLParser:
    """Extracts internal links, static script references, and passive form metadata from HTML documents."""

    @classmethod
    def parse(cls, html_content: str, base_url: str) -> Dict[str, Any]:
        """Parses HTML content and returns structured links, scripts, stylesheets, and forms."""
        result: Dict[str, Any] = {
            "links": set(),
            "scripts": set(),
            "stylesheets": set(),
            "forms": [],
            "meta_tags": {},
            "canonical_url": None
        }

        if not html_content or not isinstance(html_content, str):
            return result

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract Canonical URL
            canonical_tag = soup.find("link", rel=lambda x: x and "canonical" in x.lower())
            if canonical_tag and canonical_tag.get("href"):
                canon_norm = URLNormalizer.normalize_url(canonical_tag["href"], base_url)
                if canon_norm:
                    result["canonical_url"] = canon_norm

            # Extract Meta tags
            for meta in soup.find_all("meta"):
                name = meta.get("name") or meta.get("property")
                content = meta.get("content")
                if name and content:
                    result["meta_tags"][name.lower()] = content

            # Extract Anchor links
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                norm_url = URLNormalizer.normalize_url(href, base_url)
                if norm_url:
                    result["links"].add(norm_url)

            # Extract Script sources
            for script_tag in soup.find_all("script", src=True):
                src = script_tag["src"]
                norm_src = URLNormalizer.normalize_url(src, base_url)
                if norm_src:
                    result["scripts"].add(norm_src)

            # Extract Stylesheet links
            for link_tag in soup.find_all("link", rel=lambda x: x and "stylesheet" in x.lower()):
                href = link_tag.get("href")
                if href:
                    norm_css = URLNormalizer.normalize_url(href, base_url)
                    if norm_css:
                        result["stylesheets"].add(norm_css)

            # Extract Forms (PASSIVE METADATA EXTRACTION ONLY - NEVER SUBMITTED)
            for form in soup.find_all("form"):
                action = form.get("action") or ""
                norm_action = URLNormalizer.normalize_url(action, base_url) or base_url
                method = (form.get("method") or "GET").upper()
                enctype = form.get("enctype")

                fields: List[FormFieldSchema] = []

                # Extract inputs
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    if name:
                        fields.append(
                            FormFieldSchema(
                                name=name,
                                field_type=inp.get("type", "text").lower(),
                                default_value=inp.get("value"),
                                is_required=inp.has_attr("required")
                            )
                        )

                # Extract select fields
                for sel in form.find_all("select"):
                    name = sel.get("name")
                    if name:
                        fields.append(
                            FormFieldSchema(
                                name=name,
                                field_type="select",
                                is_required=sel.has_attr("required")
                            )
                        )

                # Extract textareas
                for txt in form.find_all("textarea"):
                    name = txt.get("name")
                    if name:
                        fields.append(
                            FormFieldSchema(
                                name=name,
                                field_type="textarea",
                                default_value=txt.string,
                                is_required=txt.has_attr("required")
                            )
                        )

                result["forms"].append(
                    FormMetadataSchema(
                        action=norm_action,
                        method=method,
                        fields=fields,
                        enctype=enctype,
                        source_url=base_url
                    )
                )

        except Exception:
            pass

        return result
