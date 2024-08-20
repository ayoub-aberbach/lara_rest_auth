<?php

namespace App\Http\Controllers;

use Throwable;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;

class UserAuth extends Controller
{
    public function register(Request $request)
    {
        try {
            $validateData = Validator::make($request->all(), [
                "fullname" => "required|string|max:40",
                "email" => "required|email:rfc,dns,spoof|unique:users,email",
                "password" => [
                    'required',
                    Password::min(12)->letters()->mixedCase()->numbers()->symbols()->uncompromised()
                ],
            ]);

            if ($validateData->fails()) {
                return response()->json(["message" => $validateData->errors()], 422);
            }

            $user = User::create([
                "email" => $request->email,
                "fullname" => $request->fullname,
                "password" => Hash::make($request->password),
            ]);

            return response()->json(["email" => $user->email, "message" => "Account Created"], 200);
        } catch (Throwable $error) {
            return response()->json(["error" => $error->getMessage()], 500);
        }
    }

    public function login(Request $request)
    {
        try {
            $validateData = Validator::make($request->all(), [
                "email" => "required|email",
                "password" => "required",
            ]);

            if ($validateData->fails()) {
                return response()->json(["message" => $validateData->errors()], 422);
            }

            if (!Auth::attempt($request->only(['email', 'password']))) {
                return response()->json(['message' => "We are unable to recognize you."], 404);
            }

            $user = User::where('email', $request->email)->first();
            $login_token = $user->createToken($user->fullname, ['user:login']);

            return response()->json([
                "email" => $user->email,
                'message' => 'Logged in successfully',
                'token' => $login_token->plainTextToken,
            ], 200);

        } catch (Throwable $error) {
            return response()->json(['error' => $error->getMessage()], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            $logged_user = $request->user();
            $logged_user->tokens()->delete();

            return response()->json(['message' => 'Logged out successfully.'], 200);
        } catch (Throwable $error) {
            return response()->json(['error' => $error->getMessage()], 500);
        }
    }

    public function updateProfileData(Request $request, string $email)
    {
        try {
            $logout = false;
            $user = User::where('email', $email)->firstOrFail();

            $validate_data = Validator::make($request->all(), [
                "new_fullname" => "nullable|string|max:40",
                "new_email" => "nullable|email:rfc,dns,spoof|unique:users,email",
                "new_password" => ["nullable", Password::min(12)->letters()->mixedCase()->numbers()->symbols()->uncompromised()],
            ]);

            if ($validate_data->fails()) {
                return response()->json(["message" => $validate_data->errors()], 400);
            }

            if (
                !$request->filled('new_email')
                and !$request->filled('new_password')
                and !$request->filled('new_fullname')
            ) {
                return response()->json(["message" => "There was no data provided."], 200);
            }

            if ($request->filled("new_email")) {
                $user->email = $request->new_email;
                $logout = true;
            }

            if ($request->filled("new_fullname")) {
                $user->fullname = $request->new_fullname;
            }

            if ($request->filled("new_password")) {
                $user->password = Hash::make($request->new_password);
                $logout = true;
            }

            $user->save();

            if ($logout) {
                $user->tokens()->delete();
                return response()->json(["message" => "Profile Updated. You have been signed out from all devices."], 200);
            }

            return response()->json(["message" => "Profile Updated"], 200);

        } catch (Throwable $error) {
            return response()->json(["error" => $error->getMessage()], 500);
        }
    }

    public function updateProfileImage(Request $request, string $email)
    {
        try {
            $user = User::where('email', $email)->firstOrFail();

            $validate_data = Validator::make($request->all(), [
                "new_profile" => "nullable|image|max:1512|mimes:png,jpg,jpeg,webp",
            ]);

            if ($validate_data->fails()) {
                return response()->json(["message" => $validate_data->errors()], 400);
            }

            if (!$request->hasFile("new_profile")) {
                return response()->json(["message" => "No picture was provided"], 403);
            }

            $file_input = $request->file("new_profile");
            $imageName = bin2hex(random_bytes(7)) . "." . $file_input->getClientOriginalExtension();
            Storage::disk("public")->putFileAs("users", $file_input, $imageName);

            // delete old image
            if (Storage::disk('public')->exists("users/$user->profile_image"))
                Storage::disk('public')->delete("users/$user->profile_image");

            $user->profile_image = $imageName;
            $user->save();

            return response()->json(["message" => "Profile picture has been updated"], 200);

        } catch (Throwable $error) {
            return response()->json(["error" => $error->getMessage()], 500);
        }
    }

    public function profileInfos(string $email)
    {
        try {
            $user = User::where('email', $email)->first();

            if (!$user->exists())
                return response()->json(['message' => 'User not found'], 422);

            return response()->json($user, 200);
        } catch (Throwable $error) {
            return response()->json(["message" => $error->getMessage()], 500);
        }
    }
}
