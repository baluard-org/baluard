//! Git provider adapters (GitHub, GitLab).
//!
//! D15: OAuth for GitHub/GitLab v1. PAT fallback. Auto-create idtty-vault repo.

use crate::error::{IdttyError, VaultError};
use std::process::Command;

pub trait ProviderAdapter {
    fn name(&self) -> &'static str;
    fn get_auth_url(&self, client_id: &str, redirect_uri: &str, state: &str) -> String;

    /// Exchange OAuth code for an access token using standard HTTP command execution.
    fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String, IdttyError>;

    /// Auto-create the repository (e.g. "idtty-vault") and return its SSH/HTTP clone URL.
    fn create_repository(
        &self,
        token: &str,
        repo_name: &str,
        private: bool,
    ) -> Result<String, IdttyError>;
}

pub struct GitHubProvider;

impl ProviderAdapter for GitHubProvider {
    fn name(&self) -> &'static str {
        "GitHub"
    }

    fn get_auth_url(&self, client_id: &str, redirect_uri: &str, state: &str) -> String {
        format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&state={}&scope=repo",
            client_id, redirect_uri, state
        )
    }

    fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String, IdttyError> {
        let url = "https://github.com/login/oauth/access_token";
        let payload = serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri
        });

        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-H",
                "Accept: application/json",
                "-d",
                &payload.to_string(),
                url,
            ])
            .output()
            .map_err(|e| VaultError::Crypto(format!("failed to execute curl: {e}")))?;

        if !output.status.success() {
            return Err(VaultError::Crypto("curl request failed".into()).into());
        }

        let resp_str = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&resp_str)
            .map_err(|e| VaultError::Corrupt(format!("invalid JSON from GitHub: {e}")))?;

        if let Some(err) = val.get("error_description") {
            return Err(VaultError::Crypto(err.as_str().unwrap_or("unknown error").into()).into());
        }

        let token = val
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| VaultError::Crypto("no access_token in response".into()))?;

        Ok(token.to_string())
    }

    fn create_repository(
        &self,
        token: &str,
        repo_name: &str,
        private: bool,
    ) -> Result<String, IdttyError> {
        let url = "https://api.github.com/user/repos";
        let payload = serde_json::json!({
            "name": repo_name,
            "private": private,
            "description": "IDtty Password Manager Vault (Git backed)"
        });

        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                &format!("Authorization: Bearer {}", token),
                "-H",
                "Accept: application/vnd.github.v3+json",
                "-H",
                "User-Agent: IDtty-Core",
                "-H",
                "Content-Type: application/json",
                "-d",
                &payload.to_string(),
                url,
            ])
            .output()
            .map_err(|e| VaultError::Crypto(format!("failed to execute curl: {e}")))?;

        if !output.status.success() {
            return Err(VaultError::Crypto("repo creation curl command failed".into()).into());
        }

        let resp_str = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&resp_str)
            .map_err(|e| VaultError::Corrupt(format!("invalid JSON response: {e}")))?;

        if let Some(err_msg) = val.get("message") {
            if val.get("errors").is_some() {
                return Err(VaultError::Crypto(
                    err_msg
                        .as_str()
                        .unwrap_or("GitHub repo creation error")
                        .into(),
                )
                .into());
            }
        }

        let clone_url = val
            .get("ssh_url")
            .or_else(|| val.get("clone_url"))
            .and_then(|u| u.as_str())
            .ok_or_else(|| VaultError::Crypto("no repository URL found in response".into()))?;

        Ok(clone_url.to_string())
    }
}

pub struct GitLabProvider;

impl ProviderAdapter for GitLabProvider {
    fn name(&self) -> &'static str {
        "GitLab"
    }

    fn get_auth_url(&self, client_id: &str, redirect_uri: &str, state: &str) -> String {
        format!(
            "https://gitlab.com/oauth/authorize?client_id={}&redirect_uri={}&state={}&response_type=code&scope=api",
            client_id, redirect_uri, state
        )
    }

    fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String, IdttyError> {
        let url = "https://gitlab.com/oauth/token";
        let payload = serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        });

        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-H",
                "Accept: application/json",
                "-d",
                &payload.to_string(),
                url,
            ])
            .output()
            .map_err(|e| VaultError::Crypto(format!("failed to execute curl: {e}")))?;

        if !output.status.success() {
            return Err(VaultError::Crypto("curl request failed".into()).into());
        }

        let resp_str = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&resp_str)
            .map_err(|e| VaultError::Corrupt(format!("invalid JSON from GitLab: {e}")))?;

        if let Some(err) = val.get("error_description") {
            return Err(VaultError::Crypto(err.as_str().unwrap_or("unknown error").into()).into());
        }

        let token = val
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| VaultError::Crypto("no access_token in response".into()))?;

        Ok(token.to_string())
    }

    fn create_repository(
        &self,
        token: &str,
        repo_name: &str,
        private: bool,
    ) -> Result<String, IdttyError> {
        let url = "https://gitlab.com/api/v4/projects";
        let visibility = if private { "private" } else { "public" };
        let payload = serde_json::json!({
            "name": repo_name,
            "visibility": visibility,
            "description": "IDtty Password Manager Vault (Git backed)"
        });

        let output = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                &format!("Authorization: Bearer {}", token),
                "-H",
                "Content-Type: application/json",
                "-d",
                &payload.to_string(),
                url,
            ])
            .output()
            .map_err(|e| VaultError::Crypto(format!("failed to execute curl: {e}")))?;

        if !output.status.success() {
            return Err(VaultError::Crypto("repo creation curl command failed".into()).into());
        }

        let resp_str = String::from_utf8_lossy(&output.stdout);
        let val: serde_json::Value = serde_json::from_str(&resp_str)
            .map_err(|e| VaultError::Corrupt(format!("invalid JSON response: {e}")))?;

        if let Some(err_msg) = val.get("message") {
            if val.get("error").is_some() || err_msg.is_object() {
                return Err(
                    VaultError::Crypto(format!("GitLab repo creation error: {err_msg}")).into(),
                );
            }
        }

        let clone_url = val
            .get("ssh_url_to_repo")
            .or_else(|| val.get("http_url_to_repo"))
            .and_then(|u| u.as_str())
            .ok_or_else(|| VaultError::Crypto("no project clone URL found in response".into()))?;

        Ok(clone_url.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_urls() {
        let gh = GitHubProvider;
        let url = gh.get_auth_url("client123", "http://redirect", "state123");
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("scope=repo"));

        let gl = GitLabProvider;
        let url = gl.get_auth_url("client123", "http://redirect", "state123");
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("scope=api"));
    }
}
