<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class DomainCheckRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Accept either a bare hostname (example.com) or a full URL (https://example.com/path).
     */
    public function rules(): array
    {
        return [
            'domain' => [
                'required',
                'string',
                'max:2048',
                'regex:#^(https?://)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(/[^\s]*)?$#i',
            ],
        ];
    }

    public function messages(): array
    {
        return [
            'domain.regex' => 'The domain must be a valid hostname or URL.',
        ];
    }

    /**
     * Allow GET ?domain= as well as JSON / form bodies.
     */
    public function validationData(): array
    {
        $data = parent::validationData();
        if (! array_key_exists('domain', $data) && $this->query('domain') !== null) {
            $data['domain'] = $this->query('domain');
        }

        return $data;
    }
}
