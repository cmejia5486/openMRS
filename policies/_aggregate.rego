# _aggregate.rego — collects all `violation` items from subpackages into `data.secmcat.violation`
import rego.v1

package secmcat

# Union of all subpackages' `violation` sets:
violation contains v if some ns; v := data.secmcat[ns].violation[_]
