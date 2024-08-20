<?php

use App\Http\Controllers\UserAuth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::post('/account/login', [UserAuth::class, 'login']);
Route::post('/account/register', [UserAuth::class, 'register']);

Route::middleware('auth:sanctum')->group(function () {
    Route::post('/account/logout', [UserAuth::class, 'logout']);
    Route::get('/account/profile/{email}', [UserAuth::class, 'profileInfos']);
    Route::post('/account/edit/photo/{email}', [UserAuth::class, 'updateProfileImage']);
    Route::patch('/account/edit/data/{email}', [UserAuth::class, 'updateProfileData']);
});
