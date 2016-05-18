<?php

namespace Bican\Roles\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Guard;
use Bican\Roles\Exceptions\RoleDeniedException;

class VerifyRole
{
    /**
     * @var \Illuminate\Contracts\Auth\Guard
     */
    protected $auth;

    /**
     * Create a new filter instance.
     *
     * @param \Illuminate\Contracts\Auth\Guard $auth
     * @return void
     */
    public function __construct(Guard $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @param int|string $role
     * @return mixed
     * @throws \Bican\Roles\Exceptions\RoleDeniedException
     */
    public function handle($request, Closure $next, $role)
    {
            $roles = $this->auth->user()->roles()->get();
            $permissions =  [];
            foreach($roles as $role){
                if(count($role->permissions()->get()->toArray()))
                    array_push($permissions,array_column($role->permissions()->get()->toArray(),'slug'));
            }
            $path_arr = explode('/',$request->path());
            if(count($path_arr) > 1){
                $path = $path_arr[0].".".$path_arr[1];
            }else{
                $path = $path_arr[0];
            }

            //dd( $path);

            if(in_array($path,array_flatten($permissions))){
                return $next($request);
            }

        throw new RoleDeniedException($role);
    }
}
