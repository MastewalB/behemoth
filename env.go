package behemoth

// Environment names the kind of deployment an application runs in. The key
// manager refuses the development secret in EnvProduction.
type Environment string

const (
	EnvProduction Environment = "production" // a deployment that serves real users
	EnvDev        Environment = "dev"        // a developer's machine or a test
)
