<?php

namespace App\Repositories\Auth;

use LaravelEasyRepository\Repository;

interface AuthRepository extends Repository
{
    public function uploadProfileImage($request);
    public function login($request);

    public function updateProfile($request);
    public function register($request);
    public function profile();
    public function logout();
    public function sendOtp($request);
    public function verifyOtp($request);
    public function changePassword($request);

    // Forgot Password Flow
    public function forgotPassword($request);
    public function verifyForgotPassword($request);
    public function resetPassword($request);
    // End Forgot Password Flow

    // Session Management
    public function listTokens();
    public function deleteToken($tokenId);
    public function logoutAll();
}
