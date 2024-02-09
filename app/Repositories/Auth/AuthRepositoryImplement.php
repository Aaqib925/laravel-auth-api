<?php

namespace App\Repositories\Auth;

use LaravelEasyRepository\Implementations\Eloquent;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;
use App\Traits\BaseResponse;
use App\Helpers\Constants;
use App\Helpers\CommonUtil;
use App\Traits\BusinessException;
use Hash;
use Otp;
use App\Jobs\JobOtp;
use App\Jobs\JobSessionMail;



class AuthRepositoryImplement extends Eloquent implements AuthRepository
{

    use BaseResponse;

    /**
     * Model class to be used in this repository for the common methods inside Eloquent
     * Don't remove or change $this->model variable name
     * @property Model|mixed $model;
     */
    protected $model;

    public function __construct(User $model)
    {
        $this->model = $model;
    }

    public function login($request)
    {
        if (!Auth::attempt($request->only('email', 'password'))) {
            throw new BusinessException(401, 'Unauthorized!', Constants::HTTP_CODE_401);
        }

        $user = $this->model::where('email', $request['email'])->firstOrFail();

        $token = $user->createToken('auth_token')->plainTextToken;

        $data = [
            'name' => $user->name,
            'time' => date('Y-m-d H:i:s'),
        ];

        try {
            dispatch(new JobSessionMail($request->email, $data));
        } catch (\Throwable $th) {
            throw $th;
        }

        return self::buildResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            (['access_token' => $token, 'user' => $user]),
            CommonUtil::generateUUID()
        );
    }

    public function register($request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8'
        ]);

        if ($validator->fails()) {
            throw new BusinessException(422, $validator->messages(), Constants::HTTP_CODE_422);
        }

        $user = $this->model::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = $user->createToken('auth_token')->plainTextToken;


        $data = [
            'name' => $request->name,
            'time' => date('Y-m-d H:i:s'),
        ];

        try {
            dispatch(new JobSessionMail($request->email, $data));
        } catch (\Throwable $th) {
            throw $th;
        }

        return self::buildResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            (['access_token' => $token, 'token_type' => 'Bearer']),
            CommonUtil::generateUUID()
        );
    }

    public function profile()
    {
        $user = Auth::user();

        return self::buildResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            (['user' => $user]),
            CommonUtil::generateUUID()
        );
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            'Success logout!!',
            CommonUtil::generateUUID()
        );
    }

    public function sendOtp($request)
    {

        $otp = new Otp;

        $otp_token = $otp->generate($request->email, 6, 5);

        $data = [
            'otp' => $otp_token->token
        ];

        // Find email and send token
        $user = $this->model::where('email', $request->email)->firstOrFail();
        $token = $user->createToken('auth_token')->plainTextToken;

        try {
            dispatch(new JobOtp($request->email, $data));
        } catch (\Throwable $th) {
            throw $th;
        }

        return self::buildResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            $token,
            CommonUtil::generateUUID()
        );
    }

    public function verifyOtp($request)
    {
        $otp = new Otp;

        $validate_token = $otp->validate($request->email, $request->otp);

        if (!$validate_token->status) {
            throw new BusinessException(422, $validate_token->message, Constants::HTTP_CODE_422);
        }

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            $validate_token->message,
            CommonUtil::generateUUID()
        );
    }

    // Change password
    public function changePassword($request)
    {
        $user = Auth::user();

        $validator = Validator::make($request->all(), [
            'old_password' => 'required|string|min:8',
            'new_password' => 'required|string|min:8'
        ]);

        if ($validator->fails()) {
            throw new BusinessException(422, $validator->messages(), Constants::HTTP_CODE_422);
        }

        if (!Hash::check($request->old_password, $user->password)) {
            throw new BusinessException(422, 'Old password is incorrect', Constants::HTTP_CODE_422);
        }

        $user->password = Hash::make($request->new_password);
        $user->save();

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            'Success change password!!',
            CommonUtil::generateUUID()
        );
    }
    // End Change Password

    // Forgot Password
    public function forgotPassword($request)
    {
        $otp = new Otp;

        $otp_token = $otp->generate($request->email, 6, 5);

        $data = [
            'otp' => $otp_token->token
        ];

        try {
            dispatch(new JobOtp($request->email, $data));
        } catch (\Throwable $th) {
            throw $th;
        }

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            'Success send otp!!',
            CommonUtil::generateUUID()
        );
    }

    public function verifyForgotPassword($request)
    {
        $otp = new Otp;

        $validate_token = $otp->validate($request->email, $request->otp);

        if (!$validate_token->status) {
            throw new BusinessException(422, $validate_token->message, Constants::HTTP_CODE_422);
        }

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            $validate_token->message,
            CommonUtil::generateUUID()
        );
    }

    public function resetPassword($request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            throw new BusinessException(422, $validator->messages(), Constants::HTTP_CODE_422);
        }


        $user = $this->model::where('email', '=', $request->email)->first();
        if (empty($user)) {
            return self::statusResponse(
                Constants::HTTP_CODE_422,
                Constants::ERROR_MESSAGE_422,
                'Email not found!!',
                CommonUtil::generateUUID()
            );
        }

        try {
            $user->password = Hash::make($request->password);
            $user->save();
        } catch (\Throwable $th) {
            throw new BusinessException(422, $th, Constants::HTTP_CODE_422);
        }

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            'Success reset password!!',
            CommonUtil::generateUUID()
        );
    }
    // End Forgot Password

    // List all sessions
    public function listTokens()
    {
        $user = Auth::user();
        return $user->tokens;
    }

    // Delete specific session
    public function deleteToken($tokenId)
    {
        $user = Auth::user();
        $token = $user->tokens()->where('id', $tokenId)->first();

        if ($token) {
            $token->delete();
            return self::statusResponse(
                Constants::HTTP_CODE_200,
                Constants::HTTP_MESSAGE_200,
                'Session deleted successfully.',
                CommonUtil::generateUUID()
            );
        }

        return self::statusResponse(
            Constants::HTTP_CODE_404,
            'Session not found.',
            'The requested Session does not exist or does not belong to this user.',
            CommonUtil::generateUUID()
        );
    }

    // Logout from all sessions
    public function logoutAll()
    {

        $user = Auth::user();
        $currentTokenId = Auth::user()->currentAccessToken()->id;

        // Delete all tokens except the current one
        $user->tokens()->where('id', '!=', $currentTokenId)->delete();

        return self::statusResponse(
            Constants::HTTP_CODE_200,
            Constants::HTTP_MESSAGE_200,
            'Logged out from all sessions except the current one successfully.',
            CommonUtil::generateUUID()
        );

        // $user = Auth::user();
        // $user->tokens()->delete();

        // return self::statusResponse(
        //     Constants::HTTP_CODE_200,
        //     Constants::HTTP_MESSAGE_200,
        //     'Logged out from all sessions successfully.',
        //     CommonUtil::generateUUID()
        // );
    }


}
