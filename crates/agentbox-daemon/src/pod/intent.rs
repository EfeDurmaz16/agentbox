use std::collections::HashMap;

use super::types::{
    ContainerRole, ContainerSpec, NetworkPolicy, PodSpec, PortMapping, ResourceLimits,
};

// ---------------------------------------------------------------------------
// Pattern types
// ---------------------------------------------------------------------------

struct RuntimePattern {
    keywords: Vec<&'static str>,
    image: &'static str,
}

struct ServicePattern {
    keywords: Vec<&'static str>,
    image: &'static str,
    port: u16,
    env_key: &'static str,
    env_value_template: &'static str,
    container_name: &'static str,
}

// ---------------------------------------------------------------------------
// IntentParser
// ---------------------------------------------------------------------------

pub struct IntentParser {
    runtimes: Vec<RuntimePattern>,
    services: Vec<ServicePattern>,
}

impl Default for IntentParser {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentParser {
    pub fn new() -> Self {
        let runtimes = vec![
            RuntimePattern {
                keywords: vec!["node", "npm", "react", "typescript"],
                image: "node:22-slim",
            },
            RuntimePattern {
                keywords: vec!["python", "pip", "django", "flask"],
                image: "python:3.12-slim",
            },
            RuntimePattern {
                keywords: vec!["rust", "cargo"],
                image: "rust:1.82-slim",
            },
            RuntimePattern {
                keywords: vec!["go", "golang"],
                image: "golang:1.23-alpine",
            },
            RuntimePattern {
                keywords: vec!["ruby", "rails"],
                image: "ruby:3.3-slim",
            },
        ];

        let services = vec![
            ServicePattern {
                keywords: vec!["postgres", "postgresql", "pg"],
                image: "postgres:16-alpine",
                port: 5432,
                env_key: "DATABASE_URL",
                env_value_template: "postgresql://postgres:postgres@localhost:5432/agentbox",
                container_name: "postgres",
            },
            ServicePattern {
                keywords: vec!["redis"],
                image: "redis:7-alpine",
                port: 6379,
                env_key: "REDIS_URL",
                env_value_template: "redis://localhost:6379",
                container_name: "redis",
            },
            ServicePattern {
                keywords: vec!["mysql", "mariadb"],
                image: "mysql:8-oracle",
                port: 3306,
                env_key: "DATABASE_URL",
                env_value_template: "mysql://root:root@localhost:3306/agentbox",
                container_name: "mysql",
            },
            ServicePattern {
                keywords: vec!["mongo", "mongodb"],
                image: "mongo:7",
                port: 27017,
                env_key: "MONGO_URL",
                env_value_template: "mongodb://localhost:27017/agentbox",
                container_name: "mongo",
            },
        ];

        Self { runtimes, services }
    }

    /// Parse a natural language request into a PodSpec.
    pub fn parse(&self, input: &str) -> PodSpec {
        let lower = input.to_lowercase();

        // Detect runtime
        let image = self.detect_runtime(&lower).unwrap_or("ubuntu:24.04");

        // Detect services
        let matched_services = self.detect_services(&lower);

        // Build containers
        let mut containers = vec![ContainerSpec {
            name: "workspace".to_string(),
            image: image.to_string(),
            command: None,
            env: HashMap::new(),
            ports: vec![],
            role: ContainerRole::Workspace,
        }];

        let mut pod_env: HashMap<String, String> = HashMap::new();

        for svc in &matched_services {
            // Sidecar container
            let mut svc_env = HashMap::new();
            // Add default passwords for services that need them
            match svc.container_name {
                "postgres" => {
                    svc_env.insert("POSTGRES_PASSWORD".to_string(), "postgres".to_string());
                    svc_env.insert("POSTGRES_DB".to_string(), "agentbox".to_string());
                }
                "mysql" => {
                    svc_env.insert("MYSQL_ROOT_PASSWORD".to_string(), "root".to_string());
                    svc_env.insert("MYSQL_DATABASE".to_string(), "agentbox".to_string());
                }
                _ => {}
            }

            containers.push(ContainerSpec {
                name: svc.container_name.to_string(),
                image: svc.image.to_string(),
                command: None,
                env: svc_env,
                ports: vec![PortMapping {
                    container_port: svc.port,
                    host_port: None,
                    protocol: "tcp".to_string(),
                }],
                role: ContainerRole::Sidecar,
            });

            // Environment variable for workspace to connect to the sidecar
            pod_env.insert(svc.env_key.to_string(), svc.env_value_template.to_string());
        }

        PodSpec {
            name: String::new(), // Caller assigns the name
            containers,
            network: NetworkPolicy::default(),
            resources: ResourceLimits::default(),
            mounts: vec![],
            env: pod_env,
            timeout_seconds: None,
            labels: HashMap::new(),
        }
    }

    /// Build a PodSpec from explicit CLI arguments (for `agentbox run`).
    pub fn from_run_args(
        &self,
        command: &[String],
        runtime: Option<&str>,
        services: &[String],
        memory_mb: u64,
    ) -> PodSpec {
        // Determine image: explicit --runtime flag, or detect from command keywords
        let image = if let Some(rt) = runtime {
            self.resolve_runtime_name(rt).unwrap_or("ubuntu:24.04")
        } else {
            // Try to detect from the command itself
            let cmd_text = command.join(" ").to_lowercase();
            self.detect_runtime(&cmd_text).unwrap_or("ubuntu:24.04")
        };

        // Build workspace container with the command
        let cmd_vec = if command.is_empty() {
            None
        } else {
            Some(command.to_vec())
        };

        let mut containers = vec![ContainerSpec {
            name: "workspace".to_string(),
            image: image.to_string(),
            command: cmd_vec,
            env: HashMap::new(),
            ports: vec![],
            role: ContainerRole::Workspace,
        }];

        let mut pod_env: HashMap<String, String> = HashMap::new();

        // Add requested service sidecars
        for svc_name in services {
            if let Some(svc) = self.find_service(&svc_name.to_lowercase()) {
                let mut svc_env = HashMap::new();
                match svc.container_name {
                    "postgres" => {
                        svc_env.insert("POSTGRES_PASSWORD".to_string(), "postgres".to_string());
                        svc_env.insert("POSTGRES_DB".to_string(), "agentbox".to_string());
                    }
                    "mysql" => {
                        svc_env.insert("MYSQL_ROOT_PASSWORD".to_string(), "root".to_string());
                        svc_env.insert("MYSQL_DATABASE".to_string(), "agentbox".to_string());
                    }
                    _ => {}
                }

                containers.push(ContainerSpec {
                    name: svc.container_name.to_string(),
                    image: svc.image.to_string(),
                    command: None,
                    env: svc_env,
                    ports: vec![PortMapping {
                        container_port: svc.port,
                        host_port: None,
                        protocol: "tcp".to_string(),
                    }],
                    role: ContainerRole::Sidecar,
                });

                pod_env.insert(svc.env_key.to_string(), svc.env_value_template.to_string());
            }
        }

        PodSpec {
            name: String::new(),
            containers,
            network: NetworkPolicy::default(),
            resources: ResourceLimits {
                memory_bytes: memory_mb * 1024 * 1024,
                cpu_shares: 2048,
            },
            mounts: vec![],
            env: pod_env,
            timeout_seconds: None,
            labels: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn detect_runtime(&self, text: &str) -> Option<&'static str> {
        for rt in &self.runtimes {
            for kw in &rt.keywords {
                if text.contains(kw) {
                    return Some(rt.image);
                }
            }
        }
        None
    }

    fn detect_services(&self, text: &str) -> Vec<&ServicePattern> {
        let mut matched = Vec::new();
        for svc in &self.services {
            for kw in &svc.keywords {
                if text.contains(kw) {
                    matched.push(svc);
                    break;
                }
            }
        }
        matched
    }

    fn resolve_runtime_name(&self, name: &str) -> Option<&'static str> {
        let lower = name.to_lowercase();
        for rt in &self.runtimes {
            for kw in &rt.keywords {
                if *kw == lower {
                    return Some(rt.image);
                }
            }
        }
        None
    }

    fn find_service(&self, name: &str) -> Option<&ServicePattern> {
        for svc in &self.services {
            for kw in &svc.keywords {
                if *kw == name {
                    return Some(svc);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_with_postgres() {
        let parser = IntentParser::new();
        let spec = parser.parse("I need a node project with postgres");

        // Workspace should use node image
        let ws = &spec.containers[0];
        assert_eq!(ws.image, "node:22-slim");
        assert!(matches!(ws.role, ContainerRole::Workspace));

        // Should have postgres sidecar
        assert_eq!(spec.containers.len(), 2);
        let pg = &spec.containers[1];
        assert_eq!(pg.image, "postgres:16-alpine");
        assert!(matches!(pg.role, ContainerRole::Sidecar));
        assert_eq!(pg.ports[0].container_port, 5432);

        // Pod env should contain DATABASE_URL
        assert!(spec.env.contains_key("DATABASE_URL"));
    }

    #[test]
    fn test_python_with_redis() {
        let parser = IntentParser::new();
        let spec = parser.parse("python flask app with redis caching");

        let ws = &spec.containers[0];
        assert_eq!(ws.image, "python:3.12-slim");

        assert_eq!(spec.containers.len(), 2);
        let redis = &spec.containers[1];
        assert_eq!(redis.image, "redis:7-alpine");
        assert_eq!(redis.ports[0].container_port, 6379);

        assert!(spec.env.contains_key("REDIS_URL"));
    }

    #[test]
    fn test_simple_node() {
        let parser = IntentParser::new();
        let spec = parser.parse("run npm test");

        let ws = &spec.containers[0];
        assert_eq!(ws.image, "node:22-slim");

        // No sidecars
        assert_eq!(spec.containers.len(), 1);
        assert!(spec.env.is_empty());
    }

    #[test]
    fn test_unknown_defaults_to_ubuntu() {
        let parser = IntentParser::new();
        let spec = parser.parse("run some random tool");

        let ws = &spec.containers[0];
        assert_eq!(ws.image, "ubuntu:24.04");
        assert_eq!(spec.containers.len(), 1);
    }

    #[test]
    fn test_from_run_args_explicit_runtime() {
        let parser = IntentParser::new();
        let spec = parser.from_run_args(
            &["npm".to_string(), "test".to_string()],
            Some("node"),
            &[],
            512,
        );

        let ws = &spec.containers[0];
        assert_eq!(ws.image, "node:22-slim");
        assert_eq!(
            ws.command,
            Some(vec!["npm".to_string(), "test".to_string()])
        );
        assert_eq!(spec.resources.memory_bytes, 512 * 1024 * 1024);
    }

    #[test]
    fn test_from_run_args_with_services() {
        let parser = IntentParser::new();
        let spec = parser.from_run_args(
            &["rails".to_string(), "db:migrate".to_string()],
            None,
            &["postgres".to_string()],
            1024,
        );

        // "rails" keyword -> ruby runtime
        let ws = &spec.containers[0];
        assert_eq!(ws.image, "ruby:3.3-slim");

        // Postgres sidecar
        assert_eq!(spec.containers.len(), 2);
        assert_eq!(spec.containers[1].image, "postgres:16-alpine");
        assert!(spec.env.contains_key("DATABASE_URL"));
    }
}
