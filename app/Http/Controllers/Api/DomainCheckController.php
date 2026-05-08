<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Http\Requests\DomainCheckRequest;
use App\Services\DomainSafetyService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

final class DomainCheckController
{
    public function __construct(
        private readonly DomainSafetyService $safety,
    ) {}

    /**
     * Check a single domain. Accepts both GET ?domain= and POST { "domain": "..." }.
     */
    public function check(DomainCheckRequest $request): JsonResponse
    {
        $domain = (string) $request->validated()['domain'];

        return response()->json([
            'success' => true,
            'data' => $this->safety->check($domain),
        ]);
    }

    /**
     * Check up to 20 domains in a single request.
     */
    public function batch(Request $request): JsonResponse
    {
        $validated = Validator::make($request->all(), [
            'domains' => ['required', 'array', 'min:1', 'max:20'],
            'domains.*' => [
                'required',
                'string',
                'max:2048',
                'regex:#^(https?://)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(/[^\s]*)?$#i',
            ],
        ])->validate();

        return response()->json([
            'success' => true,
            'data' => $this->safety->checkBatch($validated['domains']),
        ]);
    }
}
