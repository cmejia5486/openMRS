package com.lyecdevelopers.core.ui.components

import android.view.View
import android.view.ViewGroup
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentContainerView
import androidx.fragment.app.FragmentManager

@Composable
fun FragmentContainer(
    modifier: Modifier = Modifier,
    fragmentManager: FragmentManager,
    fragment: Fragment,
    tag: String? = null,
) {
    AndroidView(
        factory = { ctx ->
            FragmentContainerView(ctx).apply {
                id = View.generateViewId()
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT
                )

                val existingFragment = tag?.let { fragmentManager.findFragmentByTag(it) }

                if (existingFragment == null) {
                    fragmentManager.beginTransaction().replace(this.id, fragment, tag).commit()
                }
            }
        }, modifier = modifier
    )
}

