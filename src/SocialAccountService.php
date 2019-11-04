<?php

namespace RicLeP\SocialLogin;

use Laravel\Spark\Spark;
use App\Models\User;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Laravel\Socialite\Contracts\Provider;

use Laravel\Spark\Http\Requests\Auth\StripeRegisterRequest;
use Laravel\Spark\Http\Requests\Auth\BraintreeRegisterRequest;
use Laravel\Spark\Events\Auth\UserRegistered;
use Laravel\Spark\Contracts\Interactions\Auth\Register as SparkRegister;

class SocialAccountService
{
    /**
     * Checks for and returns an authenticated user.
     * It takes a Socialite driver and creates and social and laravel user
     * if required. If two social accounts have matching email addresses
     * then they are both linked to the same Laravel user
     *
     * @param Provider $provider
     * @return User
     */
    public function createOrGetUser(Provider $provider)
    {
        $providerUser = $provider->user();
        $providerName = class_basename($provider);

        // restore the user if it has been soft-deleted
        if (User::onlyTrashed()->whereEmail($providerUser->getEmail())->first()) {
            User::onlyTrashed()->whereEmail($providerUser->getEmail())->first()->restore();
        }

        // look for existing social auth
        $account = SocialAccount::whereProvider($providerName)
            ->whereProviderUserId($providerUser->getId())
            ->first();

        if ($account) {
            // return social auth’s Laravel user
            return $account->user;
        }

        // this is a new social auth to save it
        $account = new SocialAccount([
            'provider_user_id' => $providerUser->getId(),
            'provider' => $providerName
        ]);

        // check for an existing user by email or create a new one
		$email = $providerUser->getEmail();
		if (empty($email)){
			$email = implode('-', [
						(empty($providerUser->getName()) ? strtolower(str_replace('Provider', '', $providerName)) : str_slug($providerUser->getName())),
						$providerUser->getId()
						]);
		}

        $user = User::whereEmail($providerUser->getEmail())->first();

        if (!$user) {
            $attributes = [
                'email' => $providerUser->getEmail(),
                'name' => $providerUser->getName(),
                'password' => Hash::make(str_random(100)) // we are generating this account so add a crazy password!
            ];

            if (Spark::billsUsingBraintree()) {
                $request = BraintreeRegisterRequest::create('', 'GET', $attributes);
            } else {
                $request = StripeRegisterRequest::create('', 'GET', $attributes);
            }

            $user = Spark::interact(SparkRegister::class, [$request]);

            $user->forceFill([
                'generated_password' => true,
            ])->save();

            event(new UserRegistered($user));

            if ($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()) {
                $user->sendEmailVerificationNotification();
            }
        }

        $account->user()->associate($user);
        $account->save();

        return $user;
    }
}
