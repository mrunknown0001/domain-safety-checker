<?php

use App\Http\Controllers\Api\DomainCheckController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::prefix('domain')->middleware('throttle:30,1')->group(function (): void {
    Route::match(['get', 'post'], '/check', [DomainCheckController::class, 'check']);
    Route::post('/check-batch', [DomainCheckController::class, 'batch']);
});
