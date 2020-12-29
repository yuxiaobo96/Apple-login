package main

import (
	log "github.com/cihub/seelog"
)
var appToken = "eyJraWQiOiJlWGF1bm1MIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLlJhZGFjYXQuUmFkYWNhdENvbVRyYWNrZXIiLCJleHAiOjE2MDg4ODU2NzMsImlhdCI6MTYwODc5OTI3Mywic3ViIjoiMDAxNzc0LmM0YTA0YWM0NzY2MzQwMTk5MzUxZWQ5YzhkMTk0ZTgxLjA3MjciLCJjX2hhc2giOiJpSDhRSTBITWQ1R1E5WWRrZG5TTlhBIiwiZW1haWwiOiJxaWFuaHVhaWppeWlAaWNsb3VkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImF1dGhfdGltZSI6MTYwODc5OTI3Mywibm9uY2Vfc3VwcG9ydGVkIjp0cnVlfQ.1YYXi2hJMpIqH5q2nZO5tFbHBbjOs53siLaSa5ojz9k0Eg8dBEeogjuorIGwVpg0uQxdUN4xUGr_m_cdnFCXDGmlXKKpL04vnFEQxW9KzMZfouhlx5V3ld44yATd_nGL-42QvUNGJG_gv55wYJIikaVTUDy5WklcNr5Bm6tAWSyRbPTFWXAiboB-sQSkEPAYEdT6XCkTlXABmYEd9d7vd6VI9oWZ1id6Z868A3ERixYgxec5YuKb9o2RiSXkzMaPrzIlf83P9amiQVhetqKIF-eArE74YX3QO_ieo3tuO_BHqkUfP2kW52Sn15I3jyYG2zWiTyVxvV-zuZvvJYcHvA"
var localToken = "eyJraWQiOiI4NkQ4OEtmIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLlJhZGFjYXQuUmFkYWNhdENvbVRyYWNrZXIiLCJleHAiOjE2MDg4OTA4OTQsImlhdCI6MTYwODgwNDQ5NCwic3ViIjoiMDAwMzM2LjQyYzhjMzZkYjc1ZTRhMWFiZWM0MjI0NzQxNjE0OGYxLjEwMDgiLCJjX2hhc2giOiJWbkVrRjY2bzNQY1VYR1pOcmRfZWhRIiwiZW1haWwiOiIydXM0ZXZ3cjhrQHByaXZhdGVyZWxheS5hcHBsZWlkLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjoidHJ1ZSIsImlzX3ByaXZhdGVfZW1haWwiOiJ0cnVlIiwiYXV0aF90aW1lIjoxNjA4ODA0NDk0LCJub25jZV9zdXBwb3J0ZWQiOnRydWV9.cYmpEnu0u8HLTlC4bCFcb5-ib7R3fQJkE0dKqSS3qopmRbABCcMDuMnFwMtEtEkK_aseUVO0t8ZRHfLOoM-GBOzEI0CbUwclO39FtpH2RNE_5BGBc0761inBSf4bLbI0dIBb6X7LQetOZfpfCNTy7CTcWqdoD4mxpiJf5ISoXvNlzQTD82v52HCaEYLANTdfFKi4yV3y5fMIL6DD1PS740q4I7EoiMUxkLmTCimwr__0_Mf2X6mCbbuyfY3wuRZdaFZtC9csXKNWkUhxmOVpE22nqZdUNT3S1zblMzkpat6NVLvxw_G3t2SX5LX47cIBIzlDf5BcXb6rpUqZ73h0zQ"

func main(){
	IdToken, err := CheckIdentityToken(appToken)
	if err != nil {
		log.Error("打印错误", err)
		return
	}
	if IdToken == nil {
		return
	}
	// 返回token解析后的数据，根据业务需求进行处理
	log.Info("IdToken:", IdToken.payload.Email)

}
