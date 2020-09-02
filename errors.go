package auth

import "errors"

var (
	// ErrInvalidPassword invalid password error
	ErrInvalidPassword = errors.New("账户不存在或密码不正确")
	// ErrConfirmPassword 确认密码不正确
	ErrConfirmPassword = errors.New("确认密码不正确")
	// ErrInvalidAccount invalid account error
	ErrInvalidAccount = errors.New("无效的账户")
	// ErrUnauthorized unauthorized error
	ErrUnauthorized = errors.New("该账户还未审核")
	// ErrInvalidMoblie invalid moblie error
	ErrInvalidMoblie = errors.New("无效的手机")
	// ErrExistAccount invalid account error
	ErrExistAccount = errors.New("该手机号已经存在了")
)
