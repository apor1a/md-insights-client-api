#!/usr/bin/env python3
"""
Anomali ThreatStream integration for MD Insights Client.
Pushes OPSWAT MD Insights enrichment data to Anomali ThreatStream.
"""

import ipaddress
import json
import logging
import os
import re
from typing import Dict, Any, Optional, Union

import requests


logger = logging.getLogger(__name__)


class ThreatStreamClient:
    """Client for interacting with Anomali ThreatStream API."""
    
    def __init__(self, api_key: str = None, base_url: str = None, 
                 source_name: str = None, tlp: str = None):
        """
        Initialize ThreatStream client.
        
        Args:
            api_key: API key in format 'username:apikey'
            base_url: Base URL for ThreatStream API
            source_name: Source name for enrichments in ThreatStream
            tlp: Traffic Light Protocol setting for shared intelligence
        """
        self.api_key = api_key or os.getenv('ANOMALI_API')
        self.base_url = base_url or os.getenv('ANOMALI_URL', 'https://api.threatstream.com/api/v2')
        self.source_name = source_name or os.getenv('ANOMALI_SOURCE', 'OPSWAT_MDInSights')
        self.tlp = tlp or os.getenv('ANOMALI_TLP', 'amber')
        
        if not self.api_key:
            raise ValueError("ThreatStream API key required (set ANOMALI_API or pass api_key)")
        
        self.headers = {
            'Authorization': f'apikey {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def _get_indicator_type(self, ioc: str) -> str:
        """Determine indicator type for IOC."""
        try:
            ip = ipaddress.ip_address(ioc)
            return 'ip' if ip.version == 4 else 'ipv6'
        except ValueError:
            return 'domain'
    
    def get_or_create_indicator(self, ioc_value: str,
                                confidence: int = 50,
                                severity: str = 'medium',
                                enrichment_data: Optional[Dict[str, Any]] = None) -> Optional[int]:
        """
        Get existing indicator or create new one.
        
        Args:
            ioc_value: The IOC value (IP or domain)
            confidence: Confidence score (0-100)
            severity: Severity level
            
        Returns:
            Indicator ID if successful, None otherwise
        """
        # Always create new indicator (do not check for existing indicator first)
        itype = self._get_indicator_type(ioc_value)
        
        # Map insights data to ThreatStream indicator types
        itype_mapping = {
            'ip': 'mal_ip',
            'ipv6': 'mal_ip',
            'domain': 'mal_domain'
        }
        
        # Build tags from enrichment data so we can send enrichment in the initial create
        tags = []
        # Always add a marker tag
        tags.append({'name': 'md-insights', 'tlp': self.tlp})

        if enrichment_data:
            # Reputation-based tags
            rep = enrichment_data.get('reputation')
            if rep:
                if rep.get('score') is not None:
                    tags.append({
                        'name': f"md-insights-reputation-{rep.get('score')}",
                        'tlp': self.tlp
                    })

                if rep.get('report', {}).get('inquest', {}).get('malicious'):
                    tags.append({'name': 'md-insights-malicious', 'tlp': self.tlp})
                    for source in rep.get('report', {}).get('inquest', {}).get('sources', []):
                        tags.append({'name': f'md-insights-source-{source}', 'tlp': self.tlp})

            # C2 tag
            if enrichment_data.get('c2'):
                c2_value = enrichment_data.get('c2')
                if c2_value and c2_value != 'null':
                    sanitized = c2_value.replace(' ', '_').replace('.', '')
                    tags.append({'name': f'md-insights-c2-{sanitized}', 'tlp': self.tlp})

        body = {
            #'value': ioc_value,
            #'itype': itype_mapping.get(itype, itype),
            'source': self.source_name,
            'classification': 'private',
            'confidence': confidence,
            'severity': severity,
            'status': 'active',
            'datatext': ioc_value,
            'ip_mapping': 'mal_ip',
            'domain_mapping': 'mal_domain',
            'url_mapping': 'mal_url',
            'email_mapping': 'mal_email',
            'md5_mapping': 'mal_md5',
            'tags': tags
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/intelligence/import/',
                json=body,
                timeout=30
            )
            
            # Log the raw response for debugging
            logger.debug(f"Create API Response Status: {response.status_code}")
            logger.debug(f"Create API Response Headers: {dict(response.headers)}")
            logger.debug(f"Create API Response Body: {response.text[:1000]}")
            
            # Check for specific error codes
            if response.status_code == 401:
                logger.error(
                    f"Authentication failed (401) when creating indicator.\n"
                    f"Server response: {response.text}"
                )
                return None
            elif response.status_code == 403:
                logger.error(
                    f"Authorization failed (403) when creating indicator.\n"
                    f"Server response: {response.text}"
                )
                return None
            elif response.status_code == 409:
                # Conflict - indicator likely already exists. Attempt to extract the existing ID.
                try:
                    conflict = response.json()
                except json.JSONDecodeError:
                    conflict = None

                # Prefer direct id field
                if conflict and conflict.get('id'):
                    logger.info(f"Indicator already exists (409) with id {conflict.get('id')} for {ioc_value}")
                    return conflict.get('id')

                # Or objects list
                if conflict and conflict.get('objects') and isinstance(conflict['objects'], list) and conflict['objects']:
                    obj_id = conflict['objects'][0].get('id')
                    if obj_id:
                        logger.info(f"Indicator already exists (409) with id {obj_id} for {ioc_value}")
                        return obj_id

                # Try to extract ID from Location header if present
                loc = response.headers.get('location') or response.headers.get('Location')
                if loc:
                    m = re.search(r"/(\d+)/?$", loc)
                    if m:
                        try:
                            existing_id = int(m.group(1))
                            logger.info(f"Indicator already exists (409) with id {existing_id} (from Location header) for {ioc_value}")
                            return existing_id
                        except ValueError:
                            pass

                logger.error(
                    f"Conflict (409) when creating indicator, and could not determine existing id.\n"
                    f"Response: {response.text}"
                )
                return None
            
            response.raise_for_status()
            
            # Check if response is JSON
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type:
                logger.error(
                    f"Create API returned non-JSON response (content-type: {content_type}).\n"
                    f"Full response:\n{response.text}"
                )
                return None
            
            try:
                result = response.json()
            except json.JSONDecodeError as e:
                logger.error(
                    f"Failed to parse create response as JSON: {e}\n"
                    f"Full response:\n{response.text}"
                )
                return None

            # Accept multiple possible successful response shapes
            # - import_session_id: asynchronous import
            # - id: direct indicator id
            # - objects: list containing created indicator
            if result.get('import_session_id'):
                logger.info(f"Created import session {result['import_session_id']} for {ioc_value}")
                return result.get('import_session_id')

            if result.get('id'):
                logger.info(f"Created indicator {result['id']} for {ioc_value}")
                return result.get('id')

            if result.get('objects') and isinstance(result['objects'], list) and result['objects']:
                obj_id = result['objects'][0].get('id')
                if obj_id:
                    logger.info(f"Created indicator {obj_id} for {ioc_value}")
                    return obj_id

            logger.error(
                f"Unexpected response format when creating indicator.\n"
                f"Response: {json.dumps(result, indent=2)}"
            )
            return None
        except requests.exceptions.RequestException as e:
            logger.error(
                f"Network error creating indicator: {e}\n"
                f"Request URL: {self.base_url}/intelligence/import/\n"
                f"Request body: {json.dumps(body, indent=2)}"
            )
            return None
    # The previous add_enrichment helper has been removed in favor of sending tags
    # with the initial create call (see get_or_create_indicator(enrichment_data=...)).

def process_insights_enrichment(insights_data: Dict[str, Any], 
                               threatstream_client: ThreatStreamClient) -> Dict[str, Any]:
    """
    Process MD Insights data and push to ThreatStream.
    
    Args:
        insights_data: Response from MD Insights API
        threatstream_client: ThreatStream client instance
        
    Returns:
        Dictionary with processing results
    """
    results = {
        'processed': 0,
        'enriched': 0,
        'errors': 0,
        'details': []
    }
    
    if not insights_data.get('results'):
        logger.warning("No results in MD Insights data")
        return results
    
    for ioc_value, ioc_data in insights_data['results'].items():
        results['processed'] += 1
        
        # Determine confidence based on reputation score
        confidence = 50  # default
        severity = 'medium'  # default
        
        if ioc_data.get('reputation'):
            score = ioc_data['reputation'].get('score', 0)
            if score >= 8:
                confidence = 90
                severity = 'high'
            elif score >= 5:
                confidence = 70
                severity = 'medium'
            elif score >= 3:
                confidence = 50
                severity = 'low'
            else:
                confidence = 30
                severity = 'low'
        
        # Check if there's malicious indication
        if ioc_data.get('reputation', {}).get('report', {}).get('inquest', {}).get('malicious'):
            confidence = max(confidence, 80)
            severity = 'high'
        
        # Check for C2 data
        if ioc_data.get('c2') and ioc_data['c2'] != 'null':
            confidence = max(confidence, 85)
            severity = 'high'
        
        # Get or create indicator in ThreatStream and include enrichment tags in the initial create
        indicator_id = threatstream_client.get_or_create_indicator(
            ioc_value,
            confidence=confidence,
            severity=severity,
            enrichment_data=ioc_data
        )

        if indicator_id:
            results['enriched'] += 1
            results['details'].append({
                'ioc': ioc_value,
                'indicator_id': indicator_id,
                'status': 'enriched'
            })
            logger.info(f"Successfully created/enriched {ioc_value} (ID: {indicator_id})")
        else:
            results['errors'] += 1
            results['details'].append({
                'ioc': ioc_value,
                'status': 'creation_failed'
            })
    
    return results