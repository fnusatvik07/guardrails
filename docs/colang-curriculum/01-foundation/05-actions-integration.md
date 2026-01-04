# 🔌 Actions and Integration

**Master external system integration, security orchestration, and action-based security enforcement**

## 🎯 Learning Objectives

By the end of this section, you will:
- ✅ Understand Colang's action system and external integrations
- ✅ Implement secure API calls and system interactions
- ✅ Build security orchestration workflows with external tools
- ✅ Create custom security actions and validation functions
- ✅ Handle errors, timeouts, and security failures gracefully

---

## ⚡ Understanding Actions

### **What are Actions?**

Actions in Colang are the bridge between your guardrails and the external world. They allow you to:

- **Call external APIs** for threat intelligence, user verification, and system integration
- **Execute security tools** like vulnerability scanners, SIEM systems, and monitoring platforms
- **Perform system operations** such as logging, alerting, and automated responses
- **Integrate with databases** for user management, audit trails, and configuration storage

```colang
# Basic action syntax
execute action_name(parameter1=value1, parameter2=value2)

# Security-focused action examples
execute validate_user_credentials(user_id=$user_id, credentials=$credentials)
execute log_security_event(event_type="login_attempt", user_id=$user_id)
execute scan_content_for_threats(content=$user_message)
execute notify_security_team(alert_level="high", message=$threat_details)
```

### **Action Categories for Security**

```colang
# 1. Authentication & Authorization Actions
execute verify_mfa_token(user_id=$user_id, token=$mfa_token)
execute check_user_permissions(user_id=$user_id, resource=$resource)
execute validate_session_token(token=$session_token)
execute revoke_user_access(user_id=$user_id, reason=$security_reason)

# 2. Threat Detection & Analysis Actions  
execute analyze_message_sentiment(message=$user_input)
execute detect_malicious_patterns(content=$user_input)
execute check_ip_reputation(ip_address=$user_ip)
execute scan_for_vulnerabilities(target=$system_component)

# 3. Incident Response Actions
execute create_security_incident(severity=$severity, description=$description)  
execute isolate_user_session(user_id=$user_id, reason=$isolation_reason)
execute backup_system_state(component=$affected_component)
execute initiate_emergency_procedures(threat_level=$threat_level)

# 4. Compliance & Audit Actions
execute log_data_access(user_id=$user_id, data_type=$accessed_data)
execute generate_compliance_report(regulation=$regulation_type)
execute encrypt_sensitive_data(data=$sensitive_data, encryption_level=$level)
execute archive_conversation_logs(session_id=$session_id)

# 5. System Integration Actions  
execute update_threat_intelligence(source=$intel_source, data=$threat_data)
execute sync_user_directory(directory_service=$ldap_server)
execute send_security_notification(channel=$notification_channel, message=$alert)
execute query_security_database(query=$sql_query, params=$query_params)
```

---

## 🛡️ Security-First Action Design

### **Secure Action Implementation**

```colang
# Secure API call template
define action secure_api_call
  parameters:
    endpoint: string
    method: string (default="GET")
    headers: dict (default={})
    data: dict (default={})
    timeout: int (default=30)
    retry_attempts: int (default=3)
    
  # Input validation
  if not validate_endpoint_url($endpoint):
    raise InvalidEndpointError($endpoint)
    
  # Security headers
  $secure_headers = {
    "User-Agent": "GuardRails-Security-Agent/1.0",
    "X-Request-ID": generate_request_id(),
    "Authorization": get_api_authorization(),
    "X-API-Key": get_encrypted_api_key($endpoint)
  }
  $secure_headers.update($headers)
  
  # Rate limiting check
  if not check_rate_limit($endpoint):
    raise RateLimitExceededError($endpoint)
    
  # Attempt API call with retries
  $attempt = 0
  while $attempt < $retry_attempts:
    try:
      $response = http_request(
        url=$endpoint,
        method=$method,
        headers=$secure_headers,
        data=$data,
        timeout=$timeout,
        verify_ssl=True
      )
      
      # Validate response
      if validate_api_response($response):
        log_api_success($endpoint, $response.status_code)
        return $response
      else:
        raise InvalidResponseError($response)
        
    except (TimeoutError, ConnectionError) as $error:
      $attempt += 1
      if $attempt < $retry_attempts:
        wait(exponential_backoff($attempt))
        log_api_retry($endpoint, $attempt, $error)
      else:
        log_api_failure($endpoint, $error)
        raise APICallFailedError($endpoint, $error)
        
  # Should never reach here, but fail safely
  raise APICallFailedError($endpoint, "Max retries exceeded")

# User verification action
define action verify_user_identity
  parameters:
    user_id: string
    verification_method: string
    verification_data: dict
    
  # Security validations
  if not validate_user_id($user_id):
    log_security_event("invalid_user_id_verification_attempt", $user_id)
    raise InvalidUserIdError($user_id)
    
  # Method-specific verification
  if $verification_method == "biometric":
    $result = execute verify_biometric_data($user_id, $verification_data)
  elif $verification_method == "mfa":
    $result = execute verify_mfa_token($user_id, $verification_data)
  elif $verification_method == "knowledge_based":
    $result = execute verify_knowledge_questions($user_id, $verification_data)
  else:
    raise UnsupportedVerificationMethodError($verification_method)
    
  # Log verification attempt
  log_verification_attempt({
    "user_id": $user_id,
    "method": $verification_method,
    "result": $result["success"],
    "confidence": $result["confidence"],
    "timestamp": get_current_timestamp()
  })
  
  # Handle failed verification
  if not $result["success"]:
    increment_failed_verification_count($user_id)
    
    $failed_attempts = get_failed_verification_count($user_id)
    if $failed_attempts >= $max_failed_attempts:
      execute lock_user_account($user_id, "too_many_failed_verifications")
      
  return $result

# Threat analysis action
define action analyze_content_threats  
  parameters:
    content: string
    analysis_types: list (default=["malware", "phishing", "injection", "pii"])
    confidence_threshold: float (default=0.7)
    
  $analysis_results = {
    "threats_detected": [],
    "overall_risk_score": 0.0,
    "confidence": 0.0,
    "recommendations": []
  }
  
  # Run multiple analysis engines
  for $analysis_type in $analysis_types:
    if $analysis_type == "malware":
      $malware_result = execute scan_for_malware_indicators($content)
      if $malware_result["confidence"] >= $confidence_threshold:
        $analysis_results["threats_detected"].append($malware_result)
        
    elif $analysis_type == "phishing":  
      $phishing_result = execute detect_phishing_patterns($content)
      if $phishing_result["confidence"] >= $confidence_threshold:
        $analysis_results["threats_detected"].append($phishing_result)
        
    elif $analysis_type == "injection":
      $injection_result = execute detect_injection_attempts($content)
      if $injection_result["confidence"] >= $confidence_threshold:
        $analysis_results["threats_detected"].append($injection_result)
        
    elif $analysis_type == "pii":
      $pii_result = execute detect_pii_exposure($content)
      if $pii_result["confidence"] >= $confidence_threshold:
        $analysis_results["threats_detected"].append($pii_result)
        
  # Calculate overall risk score
  if len($analysis_results["threats_detected"]) > 0:
    $risk_scores = [threat["risk_score"] for threat in $analysis_results["threats_detected"]]
    $analysis_results["overall_risk_score"] = max($risk_scores)
    $analysis_results["confidence"] = sum([threat["confidence"] for threat in $analysis_results["threats_detected"]]) / len($analysis_results["threats_detected"])
    
    # Generate recommendations
    $analysis_results["recommendations"] = execute generate_threat_recommendations($analysis_results["threats_detected"])
    
  return $analysis_results
```

### **Security Orchestration Actions**

```colang
# Comprehensive security incident response
define action initiate_security_response
  parameters:
    incident_type: string
    severity: string
    affected_systems: list
    initial_evidence: dict
    
  # Create incident tracking record
  $incident_id = execute create_incident_record({
    "type": $incident_type,
    "severity": $severity,
    "affected_systems": $affected_systems,
    "initial_evidence": $initial_evidence,
    "created_at": get_current_timestamp(),
    "status": "active"
  })
  
  # Immediate containment actions based on severity
  if $severity == "critical":
    # Immediate isolation
    for $system in $affected_systems:
      execute isolate_system($system, $incident_id)
      
    # Emergency notifications
    execute notify_emergency_contacts($incident_id, $incident_type)
    execute activate_emergency_response_team($incident_id)
    
  elif $severity == "high":
    # Enhanced monitoring
    for $system in $affected_systems:
      execute increase_system_monitoring($system, $incident_id)
      
    # Notify security team
    execute notify_security_team($incident_id, $incident_type)
    
  # Evidence collection
  execute preserve_forensic_evidence($affected_systems, $incident_id)
  
  # Threat intelligence correlation
  $related_threats = execute correlate_with_threat_intelligence($initial_evidence)
  if len($related_threats) > 0:
    execute update_incident_with_threat_intel($incident_id, $related_threats)
    
  # Automated analysis
  $analysis_result = execute automated_incident_analysis($incident_id)
  execute update_incident_analysis($incident_id, $analysis_result)
  
  # Return incident management information
  return {
    "incident_id": $incident_id,
    "response_actions": execute get_incident_response_actions($incident_id),
    "next_steps": execute get_recommended_next_steps($incident_id),
    "estimated_impact": $analysis_result["impact_assessment"]
  }

# Multi-system security validation
define action validate_cross_system_security
  parameters:
    systems: list
    validation_types: list
    correlation_window: string (default="1 hour")
    
  $validation_results = {}
  
  # Validate each system
  for $system in $systems:
    $system_results = {}
    
    for $validation_type in $validation_types:
      if $validation_type == "access_logs":
        $system_results["access_validation"] = execute validate_access_logs($system, $correlation_window)
      elif $validation_type == "configuration":
        $system_results["config_validation"] = execute validate_system_configuration($system)
      elif $validation_type == "network_activity":
        $system_results["network_validation"] = execute validate_network_activity($system, $correlation_window)
      elif $validation_type == "integrity":
        $system_results["integrity_validation"] = execute validate_system_integrity($system)
        
    $validation_results[$system] = $system_results
    
  # Cross-system correlation
  $correlation_results = execute correlate_system_validations($validation_results, $correlation_window)
  
  # Anomaly detection across systems
  $anomalies = execute detect_cross_system_anomalies($validation_results)
  
  # Generate comprehensive report
  $final_report = {
    "individual_results": $validation_results,
    "correlation_analysis": $correlation_results,
    "detected_anomalies": $anomalies,
    "overall_security_score": execute calculate_overall_security_score($validation_results),
    "recommendations": execute generate_security_recommendations($validation_results, $anomalies)
  }
  
  return $final_report

# Automated threat hunting
define action execute_threat_hunting_workflow
  parameters:
    hunt_type: string
    time_range: string
    target_systems: list
    hunting_rules: list
    
  $hunt_session_id = execute create_hunt_session({
    "type": $hunt_type,
    "time_range": $time_range,
    "targets": $target_systems,
    "rules": $hunting_rules,
    "started_at": get_current_timestamp()
  })
  
  $hunt_results = []
  
  # Execute hunting rules across target systems
  for $rule in $hunting_rules:
    for $system in $target_systems:
      try:
        $rule_result = execute hunt_rule_on_system($rule, $system, $time_range)
        
        if $rule_result["matches"] > 0:
          $hunt_results.append({
            "rule": $rule,
            "system": $system,
            "matches": $rule_result["matches"],
            "evidence": $rule_result["evidence"],
            "confidence": $rule_result["confidence"]
          })
          
          # Immediate action for high-confidence matches
          if $rule_result["confidence"] > 0.8:
            execute flag_high_confidence_threat($hunt_session_id, $rule_result)
            
      except Exception as $error:
        execute log_hunt_error($hunt_session_id, $rule, $system, $error)
        
  # Correlate results across systems
  $correlated_findings = execute correlate_hunt_results($hunt_results)
  
  # Generate threat intelligence
  $threat_intelligence = execute generate_threat_intelligence($hunt_results, $correlated_findings)
  
  # Update threat hunting database
  execute update_hunt_database($hunt_session_id, {
    "results": $hunt_results,
    "correlations": $correlated_findings,
    "intelligence": $threat_intelligence,
    "completed_at": get_current_timestamp()
  })
  
  return {
    "session_id": $hunt_session_id,
    "findings_count": len($hunt_results),
    "high_confidence_threats": execute count_high_confidence_threats($hunt_results),
    "threat_intelligence": $threat_intelligence,
    "recommended_actions": execute generate_hunt_recommendations($hunt_results)
  }
```

---

## 🔗 External System Integration

### **API Integration Patterns**

```colang
# Threat intelligence API integration
define action query_threat_intelligence
  parameters:
    indicators: list  # IPs, domains, hashes, etc.
    sources: list (default=["virustotal", "alienvault", "threatcrowd"])
    
  $intelligence_results = {}
  
  for $source in $sources:
    $source_results = {}
    
    for $indicator in $indicators:
      try:
        if $source == "virustotal":
          $result = execute secure_api_call(
            endpoint=f"https://www.virustotal.com/vtapi/v2/file/report",
            method="POST",
            data={"apikey": get_api_key("virustotal"), "resource": $indicator}
          )
          
        elif $source == "alienvault":
          $result = execute secure_api_call(
            endpoint=f"https://otx.alienvault.com/api/v1/indicators/{$indicator}/general",
            headers={"X-OTX-API-KEY": get_api_key("alienvault")}
          )
          
        elif $source == "threatcrowd":
          $result = execute secure_api_call(
            endpoint=f"https://www.threatcrowd.org/searchApi/v2/file/report/",
            data={"resource": $indicator}
          )
          
        $source_results[$indicator] = parse_threat_intelligence_response($result, $source)
        
      except Exception as $error:
        log_threat_intel_error($source, $indicator, $error)
        $source_results[$indicator] = {"error": str($error), "available": False}
        
    $intelligence_results[$source] = $source_results
    
  # Correlate results from multiple sources
  $correlated_intelligence = execute correlate_threat_intelligence($intelligence_results)
  
  return $correlated_intelligence

# SIEM integration
define action send_to_siem
  parameters:
    event_data: dict
    siem_type: string
    priority: string (default="medium")
    
  # Format event data for specific SIEM
  if $siem_type == "splunk":
    $formatted_event = format_splunk_event($event_data, $priority)
    $endpoint = get_splunk_hec_endpoint()
    $headers = {"Authorization": f"Splunk {get_splunk_token()}"}
    
  elif $siem_type == "elasticsearch":
    $formatted_event = format_elasticsearch_event($event_data, $priority)
    $endpoint = get_elasticsearch_endpoint()
    $headers = {"Authorization": f"ApiKey {get_elasticsearch_api_key()}"}
    
  elif $siem_type == "qradar":
    $formatted_event = format_qradar_event($event_data, $priority)
    $endpoint = get_qradar_endpoint()
    $headers = {"SEC": get_qradar_token()}
    
  else:
    raise UnsupportedSIEMError($siem_type)
    
  # Send to SIEM with error handling
  try:
    $result = execute secure_api_call(
      endpoint=$endpoint,
      method="POST",
      headers=$headers,
      data=$formatted_event,
      timeout=10
    )
    
    log_siem_success($siem_type, $result["response_id"])
    return {"success": True, "siem_id": $result["response_id"]}
    
  except Exception as $error:
    log_siem_failure($siem_type, $event_data, $error)
    
    # Fallback to local logging if SIEM unavailable
    execute log_to_local_siem_buffer($formatted_event)
    return {"success": False, "error": str($error), "buffered": True}

# Identity provider integration  
define action validate_with_identity_provider
  parameters:
    user_id: string
    identity_provider: string
    validation_type: string  # "authentication", "authorization", "attributes"
    
  if $identity_provider == "active_directory":
    $ldap_config = get_ldap_configuration()
    
    if $validation_type == "authentication":
      $result = execute ldap_authenticate($user_id, $ldap_config)
    elif $validation_type == "authorization":
      $result = execute ldap_get_user_groups($user_id, $ldap_config)
    elif $validation_type == "attributes":
      $result = execute ldap_get_user_attributes($user_id, $ldap_config)
      
  elif $identity_provider == "okta":
    $okta_config = get_okta_configuration()
    
    if $validation_type == "authentication":
      $result = execute okta_validate_session($user_id, $okta_config)
    elif $validation_type == "authorization":
      $result = execute okta_get_user_permissions($user_id, $okta_config)
    elif $validation_type == "attributes":
      $result = execute okta_get_user_profile($user_id, $okta_config)
      
  elif $identity_provider == "azure_ad":
    $azure_config = get_azure_ad_configuration()
    
    if $validation_type == "authentication":
      $result = execute azure_validate_token($user_id, $azure_config)
    elif $validation_type == "authorization":
      $result = execute azure_get_user_roles($user_id, $azure_config)
    elif $validation_type == "attributes":
      $result = execute azure_get_user_claims($user_id, $azure_config)
      
  else:
    raise UnsupportedIdentityProviderError($identity_provider)
    
  # Cache results for performance (with security considerations)
  if $result["success"]:
    execute cache_identity_validation_result(
      $user_id, 
      $identity_provider, 
      $validation_type, 
      $result,
      expiry="15 minutes"
    )
    
  return $result
```

---

## 🏆 Key Takeaways

### **Action Design Principles**
- ✅ **Security First**: Every action should include security validation and logging
- ✅ **Error Handling**: Implement comprehensive error handling with secure fallbacks
- ✅ **Timeout Management**: Use appropriate timeouts to prevent hanging operations
- ✅ **Rate Limiting**: Protect external systems with appropriate rate limiting

### **Integration Best Practices**
- ✅ **API Security**: Use secure authentication and validate all API responses  
- ✅ **Data Validation**: Sanitize all data before sending to external systems
- ✅ **Credential Management**: Store and access API keys securely
- ✅ **Monitoring**: Monitor all external integrations for performance and security

### **Security Orchestration Guidelines**
- ✅ **Automated Response**: Implement appropriate automated responses for common threats
- ✅ **Human Oversight**: Require human approval for critical security actions
- ✅ **Audit Trail**: Log all security actions and decisions comprehensively
- ✅ **Rollback Capability**: Design actions with rollback and recovery mechanisms

---

## 🎉 Foundation Module Complete!

Congratulations! You've completed the **Foundation Module** of the Colang Security Curriculum. You now have a solid understanding of:

- ✅ **Colang Basics & Syntax** - The fundamental language constructs and security-first mindset
- ✅ **User & Bot Messages** - Creating secure, context-aware conversation patterns
- ✅ **Flow Control** - Building robust, security-enhanced conversation flows
- ✅ **Variables & Context** - Managing state and context securely across conversations
- ✅ **Actions & Integration** - Connecting to external systems and orchestrating security responses

**Next Steps:** 
- **Module 2:** [Intermediate Security Patterns](../02-intermediate/README.md)
  - Input Validation & Sanitization
  - Output Control & Response Filtering  
  - Multi-turn Dialog Security
  - Attack Prevention Strategies

**Ready to Level Up?** You're now prepared to tackle more advanced security scenarios and build production-ready guardrails systems!

---

**Continue Learning:** [Module 2: Intermediate Security Patterns](../02-intermediate/README.md)  
$perm_*         # Permission variables
$audit_*        # Audit and logging variables
$threat_*       # Threat detection variables
$crypto_*       # Cryptographic variables

# Examples:
$sec_clearance_level = "confidential"
$auth_token_expiry = "2024-01-15T18:00:00Z"
$perm_can_modify_users = False
$audit_last_action = "user_login"
$threat_risk_level = "medium"
$crypto_session_key = execute generate_session_key()

# Sensitive data markers (for special handling)
$SENSITIVE_user_ssn = None              # Uppercase prefix for PII
$CLASSIFIED_project_data = None         # For classified information
$RESTRICTED_api_keys = {}               # For API keys and secrets
```

### **Variable Scoping and Lifetime**

```colang
# Global variables (persist across flows and sessions)
global $system_threat_level = "low"
global $active_user_count = 0
global $system_maintenance_mode = False

# Session variables (persist during user session)
session $user_session_id = execute generate_session_id()
session $user_authenticated = False  
session $session_start_time = execute get_current_timestamp()
session $conversation_context = []

# Flow variables (local to current flow execution)
flow $current_operation = "authentication"
flow $temp_calculation_result = 0
flow $processing_stage = "validation"

# Context variables (automatically managed by system)
context $last_user_message = ""
context $last_bot_response = ""
context $conversation_turn = 0
```

---

## 🛡️ Security-Focused Variable Management

### **Sensitive Data Handling**

```colang
# Secure variable declaration with automatic protection
define flow handle_sensitive_data
  user provide personal_information
  
  # Mark variables as sensitive for special handling
  $SENSITIVE_user_email = $user_input.email
  $SENSITIVE_user_phone = $user_input.phone
  $SENSITIVE_user_address = $user_input.address
  
  # Encrypt sensitive data immediately
  $encrypted_email = execute encrypt_data($SENSITIVE_user_email)
  $encrypted_phone = execute encrypt_data($SENSITIVE_user_phone)
  
  # Clear sensitive variables from memory
  $SENSITIVE_user_email = None
  $SENSITIVE_user_phone = None
  $SENSITIVE_user_address = None
  
  # Store only encrypted versions
  $user_profile = {
    "email_encrypted": $encrypted_email,
    "phone_encrypted": $encrypted_phone,
    "created_at": execute get_current_timestamp()
  }

# PII detection and protection
define flow protect_pii_in_variables
  user said something
  
  $input_text = $last_user_message
  $pii_detected = execute detect_pii($input_text)
  
  if $pii_detected
    $pii_types = $pii_detected.types  # ["email", "ssn", "phone"]
    $sanitized_text = execute sanitize_pii($input_text)
    
    # Log PII detection (without storing the actual PII)
    $audit_pii_event = {
      "event": "pii_detected",
      "types": $pii_types,
      "user_id": $user_session_id,
      "timestamp": execute get_current_timestamp(),
      "action_taken": "sanitized"
    }
    
    execute log_security_event($audit_pii_event)
    
    # Replace original message with sanitized version
    context $last_user_message = $sanitized_text
    
    bot warn about_pii_sharing
```

### **Access Control Variables**

```colang
# Role-based access control variables
$user_roles = execute get_user_roles($user_id)
$required_permissions = []
$access_granted = False

# Permission checking system
define flow check_permissions
  # Define required permissions for different operations
  if $requested_operation == "view_user_data"
    $required_permissions = ["user.read"]
  elif $requested_operation == "modify_user_data"  
    $required_permissions = ["user.write", "user.read"]
  elif $requested_operation == "delete_user_data"
    $required_permissions = ["user.delete", "user.write", "user.read"]
  elif $requested_operation == "admin_functions"
    $required_permissions = ["admin.full"]
    
  # Check if user has all required permissions
  $access_granted = execute check_user_permissions($user_roles, $required_permissions)
  
  if not $access_granted
    $missing_permissions = execute get_missing_permissions($user_roles, $required_permissions)
    
    bot refuse insufficient_permissions
    
    # Log access denial
    $audit_access_denied = {
      "event": "access_denied", 
      "user_id": $user_id,
      "operation": $requested_operation,
      "required_permissions": $required_permissions,
      "user_permissions": $user_roles,
      "missing_permissions": $missing_permissions,
      "timestamp": execute get_current_timestamp()
    }
    
    execute log_security_event($audit_access_denied)
    abort

# Dynamic permission elevation
define flow request_permission_elevation
  user request elevated_access
  
  $current_clearance = execute get_security_clearance($user_id)
  $requested_clearance = $user_input.clearance_level
  
  if $requested_clearance > $current_clearance
    $supervisor_approval_required = True
    
    bot inform supervisor_approval_needed
    bot request supervisor_credentials
    
    user provide supervisor_credentials
    
    $supervisor_authenticated = execute verify_supervisor($supervisor_credentials)
    if $supervisor_authenticated
      $temporary_clearance = execute grant_temporary_clearance(
        user_id=$user_id,
        level=$requested_clearance,
        duration="1 hour",
        supervisor=$supervisor_credentials.supervisor_id
      )
      
      bot confirm temporary_clearance_granted
      
      # Update session variables
      session $elevated_clearance = $requested_clearance
      session $elevation_expires = execute calculate_expiry("1 hour")
      
    else
      bot refuse invalid_supervisor_credentials
      execute log_failed_elevation_attempt($user_id, $supervisor_credentials)
```

### **Threat Detection Variables**

```colang
# Threat monitoring and scoring system
global $system_threat_indicators = {
  "failed_logins": 0,
  "suspicious_patterns": 0, 
  "rate_limit_violations": 0,
  "malicious_content_attempts": 0
}

global $user_threat_scores = {}  # Dictionary of user_id -> threat_score

# Real-time threat scoring
define flow update_threat_metrics
  when SecurityEvent(event_type=$event_type, user_id=$user_id)
  
  # Update system-wide indicators
  if $event_type == "failed_login"
    $system_threat_indicators["failed_logins"] += 1
  elif $event_type == "suspicious_pattern"
    $system_threat_indicators["suspicious_patterns"] += 1
  elif $event_type == "rate_limit_violation"  
    $system_threat_indicators["rate_limit_violations"] += 1
  elif $event_type == "malicious_content"
    $system_threat_indicators["malicious_content_attempts"] += 1
    
  # Update individual user threat score
  if $user_id not in $user_threat_scores
    $user_threat_scores[$user_id] = 0.0
    
  $score_increase = execute calculate_threat_score_increase($event_type)
  $user_threat_scores[$user_id] += $score_increase
  
  # Calculate overall system threat level
  $overall_threat_level = execute assess_system_threat_level($system_threat_indicators)
  
  # Trigger appropriate response if thresholds exceeded
  if $user_threat_scores[$user_id] > $high_risk_threshold
    activate flow high_risk_user_response
  elif $overall_threat_level == "critical"
    activate flow system_wide_security_response

# Advanced behavioral analysis variables  
define flow behavioral_analysis_system
  user said something or user performed action
  
  # Initialize user behavior profile if not exists
  if $user_id not in session $user_behavior_profiles
    session $user_behavior_profiles[$user_id] = {
      "message_patterns": [],
      "time_patterns": [],
      "request_types": [],
      "interaction_frequency": 0,
      "anomaly_score": 0.0
    }
    
  $profile = session $user_behavior_profiles[$user_id]
  
  # Update behavior patterns
  $current_time = execute get_current_timestamp()
  $message_characteristics = execute analyze_message_characteristics($last_user_message)
  
  $profile["message_patterns"].append($message_characteristics)
  $profile["time_patterns"].append($current_time)
  $profile["interaction_frequency"] += 1
  
  # Keep only recent history (sliding window)
  if len($profile["message_patterns"]) > 100
    $profile["message_patterns"] = $profile["message_patterns"][-50:]
    $profile["time_patterns"] = $profile["time_patterns"][-50:]
    
  # Calculate anomaly score
  $baseline_behavior = execute get_user_baseline($user_id)
  $current_behavior = execute extract_current_behavior($profile)
  $anomaly_score = execute calculate_anomaly_score($baseline_behavior, $current_behavior)
  
  $profile["anomaly_score"] = $anomaly_score
  
  # Trigger alerts for unusual behavior
  if $anomaly_score > $anomaly_threshold
    $anomaly_details = execute analyze_anomaly_details($profile, $baseline_behavior)
    
    execute log_behavioral_anomaly({
      "user_id": $user_id,
      "anomaly_score": $anomaly_score,
      "details": $anomaly_details,
      "timestamp": $current_time
    })
    
    # Adjust security measures based on anomaly type
    if "rapid_requests" in $anomaly_details
      activate flow rate_limit_enforcement
    elif "unusual_content" in $anomaly_details
      activate flow enhanced_content_filtering
    elif "off_hours_activity" in $anomaly_details
      activate flow off_hours_verification
```

---

## 📈 Context Management Patterns

### **Conversation Context Tracking**

```colang
# Comprehensive conversation context management
session $conversation_metadata = {
  "session_id": None,
  "start_time": None,
  "turn_count": 0,
  "topics_discussed": [],
  "security_events": [],
  "user_satisfaction": None,
  "context_switches": 0
}

session $conversation_history = []  # List of {turn, user_message, bot_response, metadata}

# Context update flow
define flow update_conversation_context
  user said something or bot said something
  
  session $conversation_metadata["turn_count"] += 1
  
  # Extract topics from current exchange
  $current_topics = execute extract_topics($last_user_message)
  
  # Update topics list
  for $topic in $current_topics:
    if $topic not in session $conversation_metadata["topics_discussed"]
      session $conversation_metadata["topics_discussed"].append($topic)
      
      # Check for context switches
      if len(session $conversation_metadata["topics_discussed"]) > 1
        session $conversation_metadata["context_switches"] += 1
        
  # Add to conversation history  
  $history_entry = {
    "turn": session $conversation_metadata["turn_count"],
    "user_message": $last_user_message,
    "bot_response": $last_bot_response,
    "timestamp": execute get_current_timestamp(),
    "topics": $current_topics,
    "security_level": $current_security_level
  }
  
  session $conversation_history.append($history_entry)
  
  # Maintain sliding window of recent context
  if len(session $conversation_history) > $max_history_length
    session $conversation_history = session $conversation_history[-$context_window_size:]

# Security context awareness
define flow security_context_management
  when SecurityEvent(event_type=$event_type, severity=$severity)
  
  # Update security context
  $security_event = {
    "type": $event_type,
    "severity": $severity,
    "timestamp": execute get_current_timestamp(),
    "turn": session $conversation_metadata["turn_count"],
    "resolved": False
  }
  
  session $conversation_metadata["security_events"].append($security_event)
  
  # Adjust conversation context based on security events
  if $severity >= "high"
    # Increase security scrutiny for remaining conversation
    session $enhanced_security_mode = True
    session $security_context_expiry = execute calculate_expiry("30 minutes")
    
    # Limit conversation topics to security-safe subjects
    session $restricted_topics = execute get_restricted_topics($severity)
    
  # Update user risk profile based on conversation context
  $context_risk_factors = execute analyze_context_risk_factors(
    session $conversation_history,
    session $conversation_metadata["security_events"]
  )
  
  $updated_risk_score = execute update_user_risk_score($user_id, $context_risk_factors)
  session $current_user_risk_score = $updated_risk_score
```

### **Multi-Session Context Persistence**

```colang
# Long-term context storage and retrieval
global $user_long_term_context = {}  # user_id -> context_data

define flow load_user_context
  when UserSessionStart(user_id=$user_id)
  
  # Load persistent user context
  $stored_context = execute load_user_context_from_storage($user_id)
  
  if $stored_context:
    session $user_preferences = $stored_context["preferences"]
    session $user_security_history = $stored_context["security_history"] 
    session $user_interaction_patterns = $stored_context["interaction_patterns"]
    session $last_session_summary = $stored_context["last_session"]
    
    # Apply security measures based on history
    if $stored_context["security_history"]["violations"] > $violation_threshold
      session $enhanced_monitoring = True
      bot inform enhanced_security_active
      
    # Personalize experience based on context
    if $stored_context["preferences"]["security_level"] == "high"
      session $require_additional_verification = True
      
  else:
    # Initialize context for new user
    session $user_preferences = execute get_default_preferences()
    session $user_security_history = {"violations": 0, "events": []}
    session $user_interaction_patterns = {}
    session $last_session_summary = None
    
  # Update global context registry
  global $user_long_term_context[$user_id] = {
    "last_seen": execute get_current_timestamp(),
    "session_count": execute increment_user_session_count($user_id),
    "active": True
  }

define flow save_user_context
  when UserSessionEnd(user_id=$user_id)
  
  # Prepare context summary for storage
  $context_summary = {
    "preferences": session $user_preferences,
    "security_history": {
      "violations": session $user_security_history["violations"], 
      "events": session $user_security_history["events"][-10:], # Keep recent events
      "last_update": execute get_current_timestamp()
    },
    "interaction_patterns": execute analyze_session_patterns(
      session $conversation_history,
      session $conversation_metadata
    ),
    "last_session": {
      "duration": execute calculate_session_duration(),
      "turn_count": session $conversation_metadata["turn_count"],
      "topics": session $conversation_metadata["topics_discussed"],
      "security_events": session $conversation_metadata["security_events"],
      "satisfaction": session $conversation_metadata["user_satisfaction"],
      "end_time": execute get_current_timestamp()
    }
  }
  
  # Store context securely
  execute save_user_context_to_storage($user_id, $context_summary)
  
  # Update global registry
  global $user_long_term_context[$user_id]["active"] = False
  global $user_long_term_context[$user_id]["last_session_end"] = execute get_current_timestamp()
  
  # Clean up session variables
  session $conversation_history = None
  session $conversation_metadata = None
  session $user_security_history = None
```

### **Context-Aware Security Decisions**

```colang
# Dynamic security policy based on context
define flow context_aware_security_policy  
  user request sensitive_operation
  
  # Gather contextual information
  $time_of_day = execute get_current_hour()
  $day_of_week = execute get_current_day()
  $user_location = execute get_user_location($user_id)  # If available/consented
  $session_duration = execute get_session_duration()
  $recent_activity = execute get_recent_user_activity($user_id, "24 hours")
  
  # Calculate context-based security score
  $context_security_factors = {
    "time_factor": execute assess_time_risk($time_of_day, $day_of_week),
    "location_factor": execute assess_location_risk($user_location, $user_id),
    "session_factor": execute assess_session_risk($session_duration),
    "activity_factor": execute assess_activity_pattern_risk($recent_activity),
    "conversation_factor": execute assess_conversation_context_risk(
      session $conversation_history
    )
  }
  
  $context_risk_score = execute calculate_composite_risk_score($context_security_factors)
  
  # Apply context-aware security measures
  if $context_risk_score > $high_risk_threshold
    # High risk context - require additional verification
    bot request additional_verification
    bot explain context_based_security
    
    user provide additional_verification
    
    $verification_result = execute verify_additional_credentials($additional_verification)
    if not $verification_result
      bot refuse verification_failed
      execute log_failed_context_verification($user_id, $context_security_factors)
      abort
      
  elif $context_risk_score > $medium_risk_threshold  
    # Medium risk - enhanced monitoring
    session $enhanced_monitoring_active = True
    session $monitoring_reason = "elevated_context_risk"
    
    bot inform enhanced_monitoring_active
    
  # Proceed with operation using context-appropriate security measures
  $security_measures = execute determine_security_measures($context_risk_score)
  execute apply_security_measures($security_measures)
  
  # Log context-aware decision
  execute log_context_security_decision({
    "user_id": $user_id,
    "operation": $requested_operation,
    "context_factors": $context_security_factors,
    "risk_score": $context_risk_score,
    "measures_applied": $security_measures,
    "timestamp": execute get_current_timestamp()
  })
```

---

## 🔐 Advanced Variable Security Patterns

### **Variable Encryption and Protection**

```colang
# Encrypted variable system
define flow secure_variable_management
  # Define variables that should always be encrypted
  $encrypted_variables = [
    "user_password", "api_keys", "personal_data", 
    "financial_info", "health_data", "biometric_data"
  ]
  
  # Automatic encryption for sensitive variables
  define encrypt_if_sensitive($variable_name, $value)
    if $variable_name in $encrypted_variables:
      $encryption_key = execute get_encryption_key()
      $encrypted_value = execute encrypt_data($value, $encryption_key)
      return {"encrypted": True, "value": $encrypted_value}
    else:
      return {"encrypted": False, "value": $value}
      
  # Secure variable setter
  define set_secure_variable($name, $value)
    $protected_value = encrypt_if_sensitive($name, $value)
    execute store_variable($name, $protected_value)
    
    # Log variable access for audit
    execute log_variable_access({
      "variable": $name,
      "action": "set", 
      "encrypted": $protected_value["encrypted"],
      "user_id": $user_id,
      "timestamp": execute get_current_timestamp()
    })
    
  # Secure variable getter  
  define get_secure_variable($name)
    $stored_data = execute retrieve_variable($name)
    
    # Log access attempt
    execute log_variable_access({
      "variable": $name,
      "action": "get",
      "user_id": $user_id, 
      "timestamp": execute get_current_timestamp()
    })
    
    if $stored_data["encrypted"]:
      $decryption_key = execute get_encryption_key()
      $decrypted_value = execute decrypt_data($stored_data["value"], $decryption_key)
      return $decrypted_value
    else:
      return $stored_data["value"]

# Variable access control
define flow variable_access_control
  when VariableAccessRequested(variable_name=$var_name, user_id=$user_id)
  
  # Check if user has permission to access this variable
  $access_permissions = execute get_variable_permissions($var_name)
  $user_clearance = execute get_user_clearance($user_id)
  
  $access_granted = execute check_variable_access_permission(
    $user_clearance, 
    $access_permissions
  )
  
  if not $access_granted
    execute log_unauthorized_variable_access({
      "variable": $var_name,
      "user_id": $user_id,
      "required_clearance": $access_permissions,
      "user_clearance": $user_clearance,
      "timestamp": execute get_current_timestamp()
    })
    
    bot refuse unauthorized_variable_access
    abort
    
  # Grant access with monitoring
  session $monitored_variable_access = True
  execute monitor_variable_usage($var_name, $user_id)
```

### **Variable Auditing and Compliance**

```colang
# Comprehensive variable audit system
global $variable_audit_log = []
global $variable_access_patterns = {}

define flow variable_audit_system
  when VariableAccessed(name=$var_name, action=$action, user_id=$user_id)
  
  # Create audit entry
  $audit_entry = {
    "variable_name": $var_name,
    "action": $action,  # "read", "write", "delete", "encrypt", "decrypt"
    "user_id": $user_id,
    "session_id": session $user_session_id,
    "timestamp": execute get_current_timestamp(),
    "ip_address": execute get_user_ip_address($user_id),
    "user_agent": execute get_user_agent($user_id),
    "context": {
      "conversation_turn": session $conversation_metadata["turn_count"],
      "security_level": $current_security_level,
      "operation_context": $current_operation_context
    }
  }
  
  # Add to audit log
  global $variable_audit_log.append($audit_entry)
  
  # Update access patterns for anomaly detection
  if $user_id not in global $variable_access_patterns:
    global $variable_access_patterns[$user_id] = {}
    
  if $var_name not in global $variable_access_patterns[$user_id]:
    global $variable_access_patterns[$user_id][$var_name] = {
      "access_count": 0,
      "first_access": $audit_entry["timestamp"],
      "last_access": None,
      "access_frequency": 0.0
    }
    
  $pattern = global $variable_access_patterns[$user_id][$var_name]
  $pattern["access_count"] += 1
  $pattern["last_access"] = $audit_entry["timestamp"] 
  
  # Calculate access frequency
  $time_diff = execute calculate_time_difference(
    $pattern["first_access"], 
    $pattern["last_access"]
  )
  if $time_diff > 0:
    $pattern["access_frequency"] = $pattern["access_count"] / $time_diff
    
  # Detect unusual access patterns
  $baseline_frequency = execute get_baseline_access_frequency($user_id, $var_name)
  if $pattern["access_frequency"] > ($baseline_frequency * $anomaly_multiplier):
    execute trigger_access_anomaly_alert({
      "user_id": $user_id,
      "variable": $var_name,
      "current_frequency": $pattern["access_frequency"],
      "baseline_frequency": $baseline_frequency,
      "audit_entry": $audit_entry
    })
    
  # Compliance reporting
  if $var_name in $compliance_monitored_variables:
    execute generate_compliance_report_entry($audit_entry)
    
  # Automatic log rotation and archival
  if len(global $variable_audit_log) > $max_audit_log_size:
    $archived_entries = global $variable_audit_log[:$archive_batch_size]
    execute archive_audit_entries($archived_entries)
    global $variable_audit_log = global $variable_audit_log[$archive_batch_size:]

# Data retention and cleanup
define flow variable_lifecycle_management
  when scheduled "daily_cleanup"
  
  # Clean up expired session variables
  $current_time = execute get_current_timestamp()
  
  for $user_id in session_variables:
    $session_data = get_session_data($user_id)
    $session_age = execute calculate_time_difference(
      $session_data["start_time"], 
      $current_time
    )
    
    if $session_age > $session_expiry_time:
      # Securely clean up expired session
      execute secure_cleanup_session_variables($user_id)
      execute log_session_cleanup($user_id, $session_age)
      
  # Clean up temporary variables
  for $temp_var in get_temporary_variables():
    if $temp_var["expiry"] < $current_time:
      execute secure_delete_variable($temp_var["name"])
      
  # Compress and archive old audit logs
  $old_audit_entries = execute get_audit_entries_older_than("30 days")
  if len($old_audit_entries) > 0:
    execute compress_and_archive_audit_logs($old_audit_entries)
    execute remove_archived_audit_entries($old_audit_entries)
```

---

## 🎮 Hands-On Examples

### **Example 1: Complete Security Context System**

```colang
# Comprehensive security context management system
session $security_context = {
  "clearance_level": "public",
  "active_permissions": [],
  "security_events": [],
  "risk_score": 0.0,
  "escalation_level": 0,
  "monitoring_flags": [],
  "last_security_review": None
}

define flow initialize_security_context
  when UserSessionStart(user_id=$user_id)
  
  # Load user's base security profile
  $user_profile = execute get_user_security_profile($user_id)
  
  session $security_context = {
    "clearance_level": $user_profile["clearance_level"],
    "active_permissions": $user_profile["permissions"],
    "security_events": [],
    "risk_score": $user_profile["base_risk_score"],
    "escalation_level": 0,
    "monitoring_flags": [],
    "last_security_review": execute get_current_timestamp(),
    "authentication_methods": $user_profile["auth_methods"],
    "access_restrictions": $user_profile["restrictions"]
  }
  
  # Apply any active security advisories
  $active_advisories = execute get_active_security_advisories()
  for $advisory in $active_advisories:
    if $user_profile["clearance_level"] in $advisory["affected_levels"]:
      session $security_context["monitoring_flags"].append($advisory["type"])
      session $security_context["access_restrictions"].update($advisory["restrictions"])
      
  # Initialize behavioral baseline
  session $behavioral_baseline = execute get_user_behavioral_baseline($user_id)
  
  # Set up real-time monitoring
  execute initialize_security_monitoring($user_id, session $security_context)

define flow dynamic_security_adjustment  
  user said something or user performed action
  
  # Analyze current action for security implications
  $action_analysis = execute analyze_security_implications($last_user_message)
  
  # Update risk score based on action
  $risk_adjustment = execute calculate_risk_adjustment($action_analysis)
  session $security_context["risk_score"] += $risk_adjustment
  
  # Check if risk score exceeds thresholds
  if session $security_context["risk_score"] > $critical_risk_threshold:
    # Critical risk - immediate escalation
    session $security_context["escalation_level"] = 3
    execute initiate_critical_security_response()
    bot inform critical_security_alert
    
  elif session $security_context["risk_score"] > $high_risk_threshold:
    # High risk - enhanced monitoring and restrictions
    session $security_context["escalation_level"] = 2
    session $security_context["monitoring_flags"].append("high_risk_behavior")
    
    # Reduce permissions temporarily
    $restricted_permissions = execute apply_risk_based_restrictions(
      session $security_context["active_permissions"]
    )
    session $security_context["active_permissions"] = $restricted_permissions
    
    bot inform security_measures_enhanced
    
  elif session $security_context["risk_score"] > $medium_risk_threshold:
    # Medium risk - additional verification for sensitive operations
    session $security_context["escalation_level"] = 1
    session $security_context["monitoring_flags"].append("elevated_monitoring")
    
    bot inform additional_verification_required
    
  # Log security context changes
  $context_change = {
    "user_id": $user_id,
    "action": $last_user_message,
    "risk_adjustment": $risk_adjustment,
    "new_risk_score": session $security_context["risk_score"],
    "new_escalation_level": session $security_context["escalation_level"],
    "timestamp": execute get_current_timestamp()
  }
  
  session $security_context["security_events"].append($context_change)
  execute log_security_context_change($context_change)
  
  # Automatic risk score decay over time (users can improve their score)
  $time_since_last_review = execute calculate_time_difference(
    session $security_context["last_security_review"],
    execute get_current_timestamp()
  )
  
  if $time_since_last_review > $risk_decay_interval:
    $decay_amount = execute calculate_risk_decay($time_since_last_review)
    session $security_context["risk_score"] = max(
      0.0, 
      session $security_context["risk_score"] - $decay_amount
    )
    session $security_context["last_security_review"] = execute get_current_timestamp()

define flow security_context_reporting
  user request security_status
  
  # Generate comprehensive security report
  $security_report = {
    "current_clearance": session $security_context["clearance_level"],
    "risk_level": execute classify_risk_level(session $security_context["risk_score"]),
    "active_monitoring": session $security_context["monitoring_flags"],
    "recent_events": session $security_context["security_events"][-5:],  # Last 5 events
    "permissions_summary": execute summarize_permissions(
      session $security_context["active_permissions"]
    ),
    "escalation_status": session $security_context["escalation_level"],
    "session_duration": execute get_session_duration(),
    "recommendations": execute generate_security_recommendations(
      session $security_context
    )
  }
  
  bot provide security_status_report($security_report)
  
  # Offer security improvement suggestions
  if session $security_context["risk_score"] > $improvement_threshold:
    $improvement_suggestions = execute generate_improvement_suggestions(
      session $security_context
    )
    bot suggest security_improvements($improvement_suggestions)
```

### **Example 2: Advanced Variable Protection System**

```colang
# Multi-tier variable protection system
define class SecureVariable:
  def __init__(self, name, value, classification, access_policy):
    self.name = name
    self.value = None  # Will be encrypted
    self.classification = classification  # "public", "internal", "confidential", "secret"
    self.access_policy = access_policy
    self.created_at = execute get_current_timestamp()
    self.accessed_by = []
    self.modification_history = []
    self.encryption_key_id = None
    
    # Encrypt value based on classification
    if classification in ["confidential", "secret"]:
      self.encryption_key_id = execute generate_encryption_key()
      self.value = execute encrypt_data(value, self.encryption_key_id)
    else:
      self.value = value
      
  def get_value(self, user_id, context):
    # Check access permissions
    access_granted = execute check_access_policy(
      self.access_policy, 
      user_id, 
      context
    )
    
    if not access_granted:
      execute log_unauthorized_access_attempt(self.name, user_id)
      raise UnauthorizedAccessError()
      
    # Log access
    self.accessed_by.append({
      "user_id": user_id,
      "timestamp": execute get_current_timestamp(),
      "context": context
    })
    
    # Return decrypted value if encrypted
    if self.encryption_key_id:
      return execute decrypt_data(self.value, self.encryption_key_id)
    else:
      return self.value
      
  def set_value(self, new_value, user_id, context):
    # Check modification permissions
    modification_allowed = execute check_modification_policy(
      self.access_policy,
      user_id,
      context
    )
    
    if not modification_allowed:
      execute log_unauthorized_modification_attempt(self.name, user_id)
      raise UnauthorizedModificationError()
      
    # Store modification history
    $old_value = self.get_value(user_id, context)  # This also checks access
    
    self.modification_history.append({
      "old_value_hash": execute hash_data($old_value),
      "new_value_hash": execute hash_data(new_value),
      "modified_by": user_id,
      "timestamp": execute get_current_timestamp(),
      "context": context
    })
    
    # Update value (encrypt if needed)
    if self.encryption_key_id:
      self.value = execute encrypt_data(new_value, self.encryption_key_id)
    else:
      self.value = new_value

# Secure variable registry
global $secure_variables = {}

define flow create_secure_variable
  # Create different types of secure variables
  
  # Public data - minimal protection
  $public_config = SecureVariable(
    name="system_status",
    value="operational", 
    classification="public",
    access_policy={"read": "any", "write": "admin"}
  )
  
  # Internal data - moderate protection
  $internal_metrics = SecureVariable(
    name="performance_metrics",
    value={"cpu": 45.2, "memory": 67.1, "network": 12.5},
    classification="internal", 
    access_policy={"read": "employee", "write": "system"}
  )
  
  # Confidential data - high protection
  $confidential_user_data = SecureVariable(
    name="user_preferences",
    value={"theme": "dark", "notifications": True, "privacy_level": "high"},
    classification="confidential",
    access_policy={"read": "user_or_admin", "write": "user_only"}
  )
  
  # Secret data - maximum protection
  $secret_api_keys = SecureVariable(
    name="external_api_keys", 
    value={"payment_gateway": "sk_live_...", "analytics": "ga_..."},
    classification="secret",
    access_policy={"read": "system_only", "write": "never"}
  )
  
  # Register variables
  global $secure_variables["system_status"] = $public_config
  global $secure_variables["performance_metrics"] = $internal_metrics
  global $secure_variables["user_preferences"] = $confidential_user_data
  global $secure_variables["external_api_keys"] = $secret_api_keys

define flow access_secure_variable
  user request_variable_access(variable_name=$var_name)
  
  # Check if variable exists
  if $var_name not in global $secure_variables:
    bot inform variable_not_found
    execute log_variable_access_attempt($var_name, $user_id, "not_found")
    abort
    
  $secure_var = global $secure_variables[$var_name]
  
  # Determine access context
  $access_context = {
    "user_clearance": execute get_user_clearance($user_id),
    "session_security": session $security_context,
    "time_of_access": execute get_current_timestamp(),
    "request_source": "user_interface",
    "justification": $user_input.justification
  }
  
  try:
    # Attempt to access variable
    $variable_value = $secure_var.get_value($user_id, $access_context)
    
    # Provide value based on classification
    if $secure_var.classification == "public":
      bot provide variable_value($variable_value)
    elif $secure_var.classification == "internal":
      bot provide sanitized_variable_value($variable_value)
    elif $secure_var.classification in ["confidential", "secret"]:
      # Only provide summary or confirmation, not actual value
      bot confirm variable_access_granted
      bot provide variable_metadata($secure_var)
      
  except UnauthorizedAccessError:
    bot refuse variable_access_denied  
    bot suggest proper_access_procedure($secure_var.access_policy)
    
  except Exception as $error:
    bot apologize for_technical_error
    execute log_variable_access_error($var_name, $user_id, $error)

define flow modify_secure_variable
  user request_variable_modification(variable_name=$var_name, new_value=$new_value)
  
  if $var_name not in global $secure_variables:
    bot inform variable_not_found
    abort
    
  $secure_var = global $secure_variables[$var_name]
  
  # Enhanced context for modifications
  $modification_context = {
    "user_clearance": execute get_user_clearance($user_id),
    "session_security": session $security_context,
    "modification_time": execute get_current_timestamp(),
    "change_justification": $user_input.justification,
    "supervisor_approval": $user_input.supervisor_approval,
    "emergency_override": $user_input.emergency_override
  }
  
  try:
    # Validate modification request
    $modification_valid = execute validate_modification_request(
      $secure_var, 
      $new_value, 
      $modification_context
    )
    
    if not $modification_valid:
      bot refuse invalid_modification_request
      abort
      
    # Apply modification
    $secure_var.set_value($new_value, $user_id, $modification_context)
    
    bot confirm variable_modified
    
    # Trigger change notifications if needed
    if $secure_var.classification in ["confidential", "secret"]:
      execute notify_security_team_of_sensitive_change(
        $var_name, 
        $user_id, 
        $modification_context
      )
      
  except UnauthorizedModificationError:
    bot refuse modification_access_denied
    bot explain required_authorization($secure_var.access_policy)
    
  except Exception as $error:
    bot apologize for_technical_error
    execute log_variable_modification_error($var_name, $user_id, $error)
```

---

## 🧪 Practice Exercises

### **Exercise 1: User Behavior Analysis System**

```colang
# TODO: Build a comprehensive user behavior analysis system
session $user_behavior_metrics = {
  # TODO: Add metrics for tracking user behavior patterns
  # Include: message frequency, topic patterns, time patterns, etc.
}

define flow analyze_user_behavior
  user said something or user performed action
  
  # TODO: Implement behavior analysis that tracks:
  # 1. Communication patterns (frequency, timing, content types)
  # 2. Request patterns (types of requests, complexity levels)
  # 3. Security-relevant behaviors (attempts, compliance)
  # 4. Anomaly detection (deviations from baseline)
  
  # TODO: Create scoring system for:
  # - Trust score (increases with good behavior)
  # - Risk score (increases with suspicious behavior)
  # - Engagement score (measures interaction quality)
  
  # TODO: Implement adaptive responses based on behavior scores
```

### **Exercise 2: Secure Configuration Management**

```colang
# TODO: Create a secure configuration management system
global $system_configuration = {
  # TODO: Define different configuration categories with appropriate security
}

define flow manage_secure_configuration
  user request configuration_change
  
  # TODO: Implement:
  # 1. Configuration validation and sanitization
  # 2. Change approval workflows (based on impact and user role)
  # 3. Rollback mechanisms for failed changes  
  # 4. Audit trails for all configuration changes
  # 5. Impact assessment before applying changes
  # 6. Automated testing of configuration changes
```

### **Exercise 3: Cross-Session Security Context**

```colang
# TODO: Build a system that maintains security context across user sessions
global $cross_session_security = {
  # TODO: Design persistent security context that survives session restarts
}

define flow maintain_cross_session_security
  when UserSessionStart(user_id=$user_id) or UserSessionEnd(user_id=$user_id)
  
  # TODO: Implement:
  # 1. Security context serialization and storage
  # 2. Context validation on session restore
  # 3. Time-based context expiration
  # 4. Cross-session threat correlation
  # 5. Progressive trust building across sessions
  # 6. Anomaly detection across session boundaries
```

---

## 🏆 Key Takeaways

### **Variable Security Fundamentals**
- ✅ **Classification System**: Always classify variables by sensitivity level
- ✅ **Access Control**: Implement role-based access for all variables
- ✅ **Encryption**: Encrypt sensitive data both in memory and storage
- ✅ **Audit Trail**: Log all variable access and modifications

### **Context Management Best Practices**
- ✅ **Scoping**: Use appropriate variable scopes (global, session, flow, context)
- ✅ **Persistence**: Implement secure persistence for long-term context
- ✅ **Cleanup**: Regularly clean up expired and temporary variables
- ✅ **Performance**: Balance context richness with system performance

### **Security-Aware Variable Patterns**
- ✅ **Threat Detection**: Use variables to track and correlate security events  
- ✅ **Behavioral Analysis**: Maintain user behavior profiles for anomaly detection
- ✅ **Risk Scoring**: Implement dynamic risk scoring based on context
- ✅ **Adaptive Security**: Adjust security measures based on variable states

### **Compliance and Governance**
- ✅ **Data Retention**: Implement appropriate data retention policies
- ✅ **Privacy Protection**: Ensure PII is properly handled and protected
- ✅ **Regulatory Compliance**: Meet industry-specific variable handling requirements
- ✅ **Change Management**: Control and audit all variable schema changes

---

**Next:** [Actions and Integration](05-actions-integration.md)