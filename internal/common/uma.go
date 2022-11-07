package common

func GetPermissionEndpointPath() string {
	return "/realms/" + Config.AuthServerRealm + "/authz/protection/permission"
}

func GetRPTEndpointPath() string {
	return "/realms/" + Config.AuthServerRealm + "/authz/protection/rpt"
}
